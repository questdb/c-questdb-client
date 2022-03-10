#if __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <questdb/linesender.h>

#include "build_env.h"
#include "memwriter.h"
#include "utf8.h"
#include "aborting_malloc.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>

#if defined(PLATFORM_UNIX)
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#elif defined(PLATFORM_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#if defined(PLATFORM_UNIX)
typedef int socketfd_t;
#define CLOSESOCKET close
typedef int errno_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#elif defined(PLATFORM_WINDOWS)
typedef SOCKET socketfd_t;
#define CLOSESOCKET closesocket
#endif

#if defined(PLATFORM_UNIX)
typedef ssize_t sock_ssize_t;
typedef size_t sock_len_t;
#elif defined(PLATFORM_WINDOWS)
typedef int sock_ssize_t;
typedef int sock_len_t;
#endif

#if defined(COMPILER_MSVC)
#define UNREACHABLE() __assume(false)
#elif defined(COMPILER_GNUC)
#define UNREACHABLE() __builtin_unreachable()
#endif

typedef enum linesender_op
{
    linesender_op_table = 1,
    linesender_op_symbol = 1 << 1,
    linesender_op_column = 1 << 2,
    linesender_op_at = 1 << 3,
    linesender_op_flush = 1 << 4
} linesender_op;

static inline const char* linesender_op_str(linesender_op op)
{
    switch (op)
    {
        case linesender_op_table:
            return "table";
        case linesender_op_symbol:
            return "symbol";
        case linesender_op_column:
            return "column";
        case linesender_op_at:
            return "at";
        case linesender_op_flush:
            return "flush";
    }
    UNREACHABLE();
}

// We encode the state we're in as a bitmask of allowable follow-up API calls.
typedef enum linesender_state
{
    linesender_state_connected =
        linesender_op_table,
    linesender_state_table_written =
        linesender_op_symbol | linesender_op_column,
    linesender_state_symbol_written =
        linesender_op_symbol | linesender_op_column | linesender_op_at,
    linesender_state_column_written =
        linesender_op_column | linesender_op_at,
    linesender_state_may_flush_or_table =
        linesender_op_flush | linesender_op_table,
    linesender_state_moribund = 0,
} linesender_state;

static inline const char* linesender_state_next_op_descr(linesender_state state)
{
    switch (state)
    {
        case linesender_state_connected:
            return "should have called `table` instead";
        case linesender_state_table_written:
            return "should have called `symbol` or `column` instead";
        case linesender_state_symbol_written:
            return "should have called `symbol`, `column` or `at` instead";
        case linesender_state_column_written:
            return "should have called `column` or `at` instead";
        case linesender_state_may_flush_or_table:
            return "should have called `flush` or `table` instead";
        case linesender_state_moribund:
            return "unrecoverable state due to previous error";
    }
    UNREACHABLE();
}

struct linesender_error
{
    int errnum;
    size_t len;
    char* msg;
};

#if defined(COMPILER_GNUC)
static linesender_error* err_printf(
    linesender_state* state,
    int errnum,
    const char* fmt,
    ...) __attribute__ ((format (printf, 3, 4)));
#endif

static linesender_error* err_printf(
    linesender_state* state,
    int errnum,
    const char* fmt,
    ...)
{
    if (state)
        *state = linesender_state_moribund;
    memwriter msg_writer;
    memwriter_open(&msg_writer, 256);
    va_list args;
    va_start(args, fmt);
    memwriter_vprintf(&msg_writer, fmt, args);
    va_end(args);
    size_t len = 0;
    char* msg = memwriter_steal_and_close(&msg_writer, &len);

    linesender_error* err = aborting_malloc(sizeof(linesender_error));
    err->errnum = errnum;
    err->len = len;
    err->msg = msg;
    return err;
}

// Threadsafe access to socket error description.
// Follow-up with call to `sock_err_str`.
static char* sock_err_str(errno_t errnum)
{
#if defined(PLATFORM_UNIX)
    size_t alloc_size = 128;
    char* buf = aborting_malloc(alloc_size);
    while (true)
    {
        switch (strerror_r(errnum, buf, alloc_size))
        {
            case 0:
                return buf;

            case ERANGE:
                alloc_size *= 2;
                buf = aborting_realloc(buf, alloc_size);
                break;

            case EINVAL:
            default:
                snprintf(buf, alloc_size, "Bad errno %d", errnum);
                return buf;
        }
    }
#elif defined(PLATFORM_WINDOWS)
    char *msg = NULL;
    if (!FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errnum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msg,
        0,
        NULL))
    {
        const errno_t fmt_error = GetLastError();
        // 64 > (len('Error  whilst formatting socket error ')
        //       + (2 * len(str(max_len_errno))) + 1)
        // where: max_len_errno == -2 ** 31
        const size_t alloc_size = 64;
        msg = LocalAlloc(LMEM_FIXED, alloc_size);
        if (!msg)
            abort();
        snprintf(
            msg,
            alloc_size,
            "Error %d whilst formatting socket error %d",
            fmt_error, errnum);
    }
    return msg;
#endif
}

static void sock_err_str_free(char* msg)
{
#if defined(PLATFORM_UNIX)
    free(msg);
#elif defined(PLATFORM_WINDOWS)
    LocalFree(msg);
#endif
}

static errno_t get_last_sock_err()
{
#if defined(PLATFORM_UNIX)
    return errno;
#elif defined(PLATFORM_WINDOWS)
    return WSAGetLastError();
#endif
}

int linesender_error_errnum(const linesender_error* err)
{
    return err->errnum;
}

const char* linesender_error_msg(const linesender_error* err, size_t* len_out)
{
    *len_out = err->len;
    return err->msg;
}

void linesender_error_free(linesender_error* err)
{
    free(err->msg);
    free(err);
}

static inline size_t escape_char(char buf[5], char c)
{
    if ((c == '"') || (c == '\''))
    {
        buf[0] = '\\';
        buf[1] = c;
        return 2;
    }
    else if ((' ' <= c) && (c <= '~'))
    {
        buf[0] = c;
        return 1;
    }
    else
    {
        switch (c)
        {
        case '\0':
            buf[0] = '\\';
            buf[1] = '0';
            return 2;
        case '\t':
            buf[0] = '\\';
            buf[1] = 't';
            return 2;
        case '\n':
            buf[0] = '\\';
            buf[1] = 'n';
            return 2;
        case '\r':
            buf[0] = '\\';
            buf[1] = 'r';
            return 2;
        default:
            snprintf(buf, 5, "\\x%02x", (uint8_t)c);
            return 4;
        }
    }
}

/** An ASCII-safe description of a binary buffer. Trimmed if too long. */
static char* describe_buf(size_t len, const char* buf, size_t* descr_len_out)
{
    const size_t max_len = 100;
    const bool trim = len >= max_len;
    const size_t working_len = trim
        ? max_len - 3  // 3 here for trailing "..."
        : len;
    memwriter writer;

    // If every byte needs escaping we'll need to 4 times as many bytes,
    // + 1 for trailing \0 added by printf functions.
    memwriter_open(&writer, working_len * 4 + 1);
    for (size_t index = 0; index < working_len; ++index)
    {
        const char c = buf[index];
        char escaped_buf[5];
        const size_t escaped_len = escape_char(escaped_buf, c);
        memwriter_str(&writer, escaped_len, escaped_buf);
    }

    if (trim)
        memwriter_str(&writer, 3, "...");

    return memwriter_steal_and_close(&writer, descr_len_out);
}

static struct addrinfo* resolve_addr(
    const char* host,
    const char* port,
    linesender_error** err_out)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* addr = NULL;
    errno_t gai_err_code = getaddrinfo(host, port, &hints, &addr);
    if (gai_err_code)
    {
        size_t host_descr_len = 0;
        char* host_descr = describe_buf(strlen(host), host, &host_descr_len);
        if (port)
        {
            size_t port_descr_len = 0;
            char* port_descr = describe_buf(
                strlen(port), port, &port_descr_len);
#if defined(PLATFORM_UNIX)
            const char* gai_err_descr = gai_strerror(gai_err_code);
#elif defined(PLATFORM_WINDOWS)
            // `gai_strerror` is thread-safe on Linux, but not Windows
            // where we need to use `FormatMessage` instead.
            char* gai_err_descr = sock_err_str(gai_err_code);
#endif
            *err_out = err_printf(
                NULL,
                0,  // Note: gai_err_code != errno
                "Could not resolve \"%.*s:%.*s\": %s",
                (int)host_descr_len,
                host_descr,
                (int)port_descr_len,
                port_descr,
                gai_err_descr);
            free(host_descr);
            free(port_descr);
#if defined(PLATFORM_WINDOWS)
            sock_err_str_free(gai_err_descr);
#endif
        }
        else
        {
            *err_out = err_printf(
                NULL,
                0,  // Note: gai_err_code != errno
                "Could not resolve \"%.*s\": %s",
                (int)host_descr_len,
                host_descr,
                gai_strerror(gai_err_code));
            free(host_descr);
        }
        return NULL;
    }
    return addr;
}

static inline bool check_state(
    linesender_state* state,
    linesender_op op,
    linesender_error** err_out)
{
    if (*state & op)
        return true;

    const char* op_descr = linesender_op_str(op);
    const char* next_op_descr = linesender_state_next_op_descr(*state);
    *err_out = err_printf(
        state,
        0,
        "State error: Bad call to `%s`, %s. Must now call `close`.",
        op_descr,
        next_op_descr);
    return false;
}

struct linesender
{
    socketfd_t sock_fd;
    struct addrinfo* dest_info;
    linesender_state state;
    memwriter writer;
    size_t last_line_start;
};

linesender* linesender_connect(
    const char* net_interface,
    const char* host,
    const char* port,
    linesender_error** err_out)
{
    struct addrinfo* dest_info = NULL;
    struct addrinfo* if_info = NULL;
    socketfd_t sock_fd = 0;

    dest_info = resolve_addr(host, port, err_out);
    if (!dest_info)
        goto error_cleanup;

    if_info = resolve_addr(net_interface, NULL, err_out);
    if (!if_info)
        goto error_cleanup;

    sock_fd = socket(
        dest_info->ai_family,
        dest_info->ai_socktype,
        dest_info->ai_protocol);
    if (sock_fd == INVALID_SOCKET)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            NULL,
            errnum,
            "Could not open TCP socket: %s.",
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }

#if defined(PLATFORM_UNIX)
    if (fcntl(sock_fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            NULL,
            errnum,
            "Could not set FD_CLOEXEC on socket: %s.",
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }
#endif

    int no_delay = 1;
    if (setsockopt(
        sock_fd,
        IPPROTO_TCP,
        TCP_NODELAY,
        (char *) &no_delay,
        sizeof(int)) == SOCKET_ERROR)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            NULL,
            errnum,
            "Could not set TCP_NODELAY: %s.",
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }

    sock_len_t addrlen = (sock_len_t)dest_info->ai_addrlen;
    if (bind(sock_fd, if_info->ai_addr, addrlen) == SOCKET_ERROR)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            NULL,
            errnum,
            "Could not bind to interface address \"%s\": %s.",
            net_interface,
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }

    if (connect(sock_fd, dest_info->ai_addr, addrlen) == SOCKET_ERROR)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            NULL,
            errnum,
            "Could not connect to \"%s:%s\": %s.",
            host,
            port,
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }

    freeaddrinfo(if_info);
    if_info = NULL;

    memwriter writer;
    memwriter_open(&writer, 65536);  // 64KB initial buffer size.

    linesender* sender = aborting_malloc(sizeof(linesender));
    sender->sock_fd = sock_fd;
    sender->dest_info = dest_info;
    sender->state = linesender_state_connected;
    sender->writer = writer;
    sender->last_line_start = 0;
    return sender;

error_cleanup:
    if (dest_info)
        freeaddrinfo(dest_info);
    if (if_info)
        freeaddrinfo(if_info);
    if (sock_fd)
        CLOSESOCKET(sock_fd);
    return NULL;
}

static inline bool check_utf8(
    linesender_state* state,
    size_t len,
    const char* buf,
    linesender_error** err_out)
{
    utf8_error u8err;
    if (!utf8_check(len, buf, &u8err))
    {
        size_t buf_descr_len = 0;
        char* buf_descr = describe_buf(len, buf, &buf_descr_len);
        if (u8err.need_more)
        {
            *err_out = err_printf(
                state,
                0,
                "Bad string \"%.*s\": "
                "Invalid UTF-8. "
                "Incomplete multi-byte codepoint at end of string. "
                "Bad codepoint starting at byte index %" PRI_SIZET ".",
                (int)buf_descr_len,
                buf_descr,
                u8err.valid_up_to);
        }
        else
        {
            *err_out = err_printf(
                state,
                0,
                "Bad string \"%.*s\": "
                "Invalid UTF-8. "
                "Illegal codepoint starting at byte index %" PRI_SIZET ".",
                (int)buf_descr_len,
                buf_descr,
                u8err.valid_up_to);
        }
        free(buf_descr);
        return false;
    }
    return true;
}

static inline bool check_key_name(
    linesender_state* state,
    size_t len,
    const char* name,
    linesender_error** err_out)
{
    if (!len)
    {
        *err_out = err_printf(
            state,
            0,
            "table, symbol and column names must have a non-zero length.");
        return false;
    }

    if (!check_utf8(state, len, name, err_out))
        return false;

    for (size_t index = 0; index < len; ++index)
    {
        const char c = name[index];
        switch (c)
        {
            case ' ':
            case '?':
            case '.':
            case ',':
            case '\'':
            case '\"':
            case '\\':
            case '/':
            case '\0':
            case ':':
            case ')':
            case '(':
            case '+':
            case '-':
            case '*':
            case '%':
            case '~':
                {
                    size_t name_descr_len = 0;
                    char* name_descr = describe_buf(len, name, &name_descr_len);
                    char escaped_buf[5];
                    const size_t escaped_len = escape_char(escaped_buf, c);
                    *err_out = err_printf(
                        state,
                        0,
                        "Bad string \"%.*s\": "
                        "table, symbol and column names can't contain a '%.*s' "
                        "character, which was found at byte position "
                        "%" PRI_SIZET ".",
                        (int)name_descr_len,
                        name_descr,
                        (int)escaped_len,
                        escaped_buf,
                        index);
                    free(name_descr);
                }
                return false;
            default:
                break;
        }

        // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE', aka UTF-8 BOM
        // if it appears anywhere in the string.
        if ((c == '\xef') &&
            ((index + 2) < len) &&
            (name[index + 1] == '\xbb') &&
            (name[index + 2] == '\xbf'))
        {
            size_t name_descr_len = 0;
            char* name_descr = describe_buf(len, name, &name_descr_len);
            *err_out = err_printf(
                state,
                0,
                "Bad string \"%.*s\": "
                "table, symbol and column names can't contain a UTF-8 BOM "
                "character, which was found at byte position "
                "%" PRI_SIZET ".",
                (int)name_descr_len,
                name_descr,
                index);
            free(name_descr);
            return false;
        }
    }
    return true;
}

static inline bool must_escape_unquoted(char c)
{
    switch (c)
    {
        case ' ':
        case ',':
        case '=':
        case '\n':
        case '\r':
        case '"':
        case '\\':
            return true;
        default:
            return false;
    }
}

static inline bool must_escape_quoted(char c)
{
    switch (c)
    {
        case '\n':
        case '\r':
        case '"':
        case '\\':
            return true;
        default:
            return false;
    }
}

#define DEFINE_WRITE_ESCAPED_FN(FN_NAME, CHECK_ESCAPE_FN, QUOTING_FN)          \
    static void FN_NAME(memwriter* writer, size_t len, const char* s)          \
    {                                                                          \
        size_t to_escape = 0;                                                  \
        for (size_t index = 0; index < len; ++index)                           \
            if (CHECK_ESCAPE_FN(s[index]))                                     \
                ++to_escape;                                                   \
        QUOTING_FN;                                                            \
        if (!to_escape)                                                        \
        {                                                                      \
            memwriter_str(writer, len, s);                                     \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            char* buf = memwriter_book(writer, len + to_escape);               \
            const char* init_buf = buf;                                        \
            for (size_t index = 0; index < len; ++index)                       \
            {                                                                  \
                const char c = s[index];                                       \
                if (must_escape_unquoted(c))                                   \
                    *buf++ = '\\';                                             \
                *buf++ = c;                                                    \
            }                                                                  \
            memwriter_advance(writer, (size_t)(buf - init_buf));               \
        }                                                                      \
        QUOTING_FN;                                                            \
    }

DEFINE_WRITE_ESCAPED_FN(
    write_escaped_unquoted,
    must_escape_unquoted,
    NULL)

DEFINE_WRITE_ESCAPED_FN(
    write_escaped_quoted,
    must_escape_quoted,
    (memwriter_char(writer, '"')))

bool linesender_table(
    linesender* sender,
    size_t name_len,
    const char* name,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_table, err_out))
        return false;
    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;

    write_escaped_unquoted(&sender->writer, name_len, name);

    sender->state = linesender_state_table_written;
    return true;
}

bool linesender_symbol(
    linesender* sender,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_symbol, err_out))
        return false;
    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;
    if (!check_utf8(&sender->state, value_len, value, err_out))
        return false;

    memwriter_char(&sender->writer, ',');
    write_escaped_unquoted(&sender->writer, name_len, name);
    memwriter_char(&sender->writer, '=');
    write_escaped_unquoted(&sender->writer, value_len, value);

    sender->state = linesender_state_symbol_written;
    return true;
}

static inline bool write_column_key(
    linesender* sender,
    size_t name_len,
    const char* name,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_column, err_out))
        return false;

    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;

    const char separator =
        (sender->state & linesender_op_symbol)
            ? ' '
            : ',';
    memwriter_char(&sender->writer, separator);
    write_escaped_unquoted(&sender->writer, name_len, name);
    memwriter_char(&sender->writer, '=');
    sender->state = linesender_state_column_written;
    return true;
}

bool linesender_column_bool(
    linesender* sender,
    size_t name_len,
    const char* name,
    bool value,
    linesender_error** err_out)
{
    if (!write_column_key(sender, name_len, name, err_out))
        return false;
    memwriter_char(&sender->writer, value ? 't' : 'f');
    return true;
}

bool linesender_column_i64(
    linesender* sender,
    size_t name_len,
    const char* name,
    int64_t value,
    linesender_error** err_out)
{
    if (!write_column_key(sender, name_len, name, err_out))
        return false;
    memwriter_i64(&sender->writer, value);
    memwriter_char(&sender->writer, 'i');
    return true;
}

bool linesender_column_f64(
    linesender* sender,
    size_t name_len,
    const char* name,
    double value,
    linesender_error** err_out)
{
    if (!write_column_key(sender, name_len, name, err_out))
        return false;
    memwriter_f64(&sender->writer, value);
    return true;
}

bool linesender_column_str(
    linesender* sender,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out)
{
    if (!check_utf8(&sender->state, value_len, value, err_out))
        return false;
    if (!write_column_key(sender, name_len, name, err_out))
        return false;
    write_escaped_quoted(&sender->writer, value_len, value);
    return true;
}

static inline void update_last_line_start(linesender* sender)
{
    sender->last_line_start = linesender_pending_size(sender);
}

bool linesender_at(
    linesender* sender,
    int64_t epoch_nanos,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_at, err_out))
        return false;
    memwriter* writer = &sender->writer;
    memwriter_char(writer, ' ');
    memwriter_i64(writer, epoch_nanos);
    memwriter_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = linesender_state_may_flush_or_table;
    return true;
}

bool linesender_at_now(
    linesender* sender,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_at, err_out))
        return false;
    memwriter_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = linesender_state_may_flush_or_table;
    return true;
}

size_t linesender_pending_size(linesender* sender)
{
    return (sender->state != linesender_state_moribund)
        ? memwriter_len(&sender->writer)
        : 0;
}

static inline bool send_all(linesender* sender, sock_len_t len, const char* buf)
{
    while (len)
    {
        sock_ssize_t send_res = send(
            sender->sock_fd,
            buf,
            len,
            0);
        if (send_res != SOCKET_ERROR)
        {
            buf += (size_t)send_res;
            len -= (size_t)send_res;
        }
        else
        {
            return false;
        }
    }
    return true;
}

bool linesender_flush(
    linesender* sender,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_flush, err_out))
        return false;

    size_t len = 0;
    const char* buf = memwriter_peek(&sender->writer, &len);

    const bool send_ok = send_all(sender, (sock_len_t)len, buf);
    if (!send_ok)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            &sender->state,
            errnum,
            "Could not flush buffered messages: %s.",
            err_descr);
        sock_err_str_free(err_descr);
        return false;
    }

    memwriter_rewind(&sender->writer);
    sender->state = linesender_state_connected;
    return true;
}

bool linesender_must_close(linesender* sender)
{
    return sender->state == linesender_state_moribund;
}

void linesender_close(linesender* sender)
{
    memwriter_close(&sender->writer);
    CLOSESOCKET(sender->sock_fd);
    freeaddrinfo(sender->dest_info);
    free(sender);
}
