/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#if __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <questdb/ilp/line_sender.h>

#include "build_env.h"
#include "mem_writer.h"
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

typedef enum line_sender_op
{
    line_sender_op_table = 1,
    line_sender_op_symbol = 1 << 1,
    line_sender_op_column = 1 << 2,
    line_sender_op_at = 1 << 3,
    line_sender_op_flush = 1 << 4
} line_sender_op;

static inline const char* line_sender_op_str(line_sender_op op)
{
    switch (op)
    {
        case line_sender_op_table:
            return "table";
        case line_sender_op_symbol:
            return "symbol";
        case line_sender_op_column:
            return "column";
        case line_sender_op_at:
            return "at";
        case line_sender_op_flush:
            return "flush";
    }
    UNREACHABLE();
}

// We encode the state we're in as a bitmask of allowable follow-up API calls.
typedef enum line_sender_state
{
    line_sender_state_connected =
        line_sender_op_table,
    line_sender_state_table_written =
        line_sender_op_symbol | line_sender_op_column,
    line_sender_state_symbol_written =
        line_sender_op_symbol | line_sender_op_column | line_sender_op_at,
    line_sender_state_column_written =
        line_sender_op_column | line_sender_op_at,
    line_sender_state_may_flush_or_table =
        line_sender_op_flush | line_sender_op_table,
    line_sender_state_moribund = 0,
} line_sender_state;

static inline const char* line_sender_state_next_op_descr(
    line_sender_state state)
{
    switch (state)
    {
        case line_sender_state_connected:
            return "should have called `table` instead";
        case line_sender_state_table_written:
            return "should have called `symbol` or `column` instead";
        case line_sender_state_symbol_written:
            return "should have called `symbol`, `column` or `at` instead";
        case line_sender_state_column_written:
            return "should have called `column` or `at` instead";
        case line_sender_state_may_flush_or_table:
            return "should have called `flush` or `table` instead";
        case line_sender_state_moribund:
            return "unrecoverable state due to previous error";
    }
    UNREACHABLE();
}

struct line_sender_error
{
    line_sender_error_code code;
    size_t len;
    char* msg;
};

#if defined(COMPILER_GNUC)
static line_sender_error* err_printf(
    line_sender_state* state,
    line_sender_error_code code,
    const char* fmt,
    ...) __attribute__ ((format (printf, 3, 4)));
#endif

static line_sender_error* err_printf(
    line_sender_state* state,
    line_sender_error_code code,
    const char* fmt,
    ...)
{
    if (state)
        *state = line_sender_state_moribund;
    mem_writer msg_writer;
    mem_writer_open(&msg_writer, 256);
    va_list args;
    va_start(args, fmt);
    mem_writer_vprintf(&msg_writer, fmt, args);
    va_end(args);
    size_t len = 0;
    char* msg = mem_writer_steal_and_close(&msg_writer, &len);

    line_sender_error* err = aborting_malloc(sizeof(line_sender_error));
    err->code = code;
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

line_sender_error_code line_sender_error_get_code(const line_sender_error* err)
{
    return err->code;
}

const char* line_sender_error_msg(const line_sender_error* err, size_t* len_out)
{
    *len_out = err->len;
    return err->msg;
}

void line_sender_error_free(line_sender_error* err)
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
    mem_writer writer;

    // If every byte needs escaping we'll need to 4 times as many bytes,
    // + 1 for trailing \0 added by printf functions.
    mem_writer_open(&writer, working_len * 4 + 1);
    for (size_t index = 0; index < working_len; ++index)
    {
        const char c = buf[index];
        char escaped_buf[5];
        const size_t escaped_len = escape_char(escaped_buf, c);
        mem_writer_str(&writer, escaped_len, escaped_buf);
    }

    if (trim)
        mem_writer_str(&writer, 3, "...");

    return mem_writer_steal_and_close(&writer, descr_len_out);
}

static struct addrinfo* resolve_addr(
    const char* host,
    const char* port,
    line_sender_error** err_out)
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
                line_sender_error_could_not_resolve_addr,
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
                line_sender_error_could_not_resolve_addr,
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
    line_sender_state* state,
    line_sender_op op,
    line_sender_error** err_out)
{
    if (*state & op)
        return true;

    const char* op_descr = line_sender_op_str(op);
    const char* next_op_descr = line_sender_state_next_op_descr(*state);
    *err_out = err_printf(
        state,
        line_sender_error_invalid_api_call,
        "State error: Bad call to `%s`, %s. Must now call `close`.",
        op_descr,
        next_op_descr);
    return false;
}

#if defined(PLATFORM_WINDOWS)
static void init_winsock()
{
    WORD vers_req = MAKEWORD(2, 2);
    WSADATA wsa_data;
    int err = WSAStartup(vers_req, &wsa_data);
    if (err != 0)
    {
        fprintf(
            stderr,
            "Socket init failed. WSAStartup failed with error: %d",
            err);
        abort();
    }
}

static void release_winsock()
{
    if (WSACleanup() != 0)
    {
        fprintf(
            stderr,
            "Releasing sockets failed: WSACleanup failed with error: %d",
            WSAGetLastError());
        abort();
    }
}
#endif

struct line_sender
{
    socketfd_t sock_fd;
    struct addrinfo* dest_info;
    line_sender_state state;
    mem_writer writer;
    size_t last_line_start;
};

line_sender* line_sender_connect(
    const char* net_interface,
    const char* host,
    const char* port,
    line_sender_error** err_out)
{
#if defined(PLATFORM_WINDOWS)
    init_winsock();
#endif

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
            line_sender_error_socket_error,
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
            line_sender_error_socket_error,
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
            line_sender_error_socket_error,
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
            line_sender_error_socket_error,
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
            line_sender_error_socket_error,
            "Could not connect to \"%s:%s\": %s.",
            host,
            port,
            err_descr);
        sock_err_str_free(err_descr);
        goto error_cleanup;
    }

    freeaddrinfo(if_info);
    if_info = NULL;

    mem_writer writer;
    mem_writer_open(&writer, 65536);  // 64KB initial buffer size.

    line_sender* sender = aborting_malloc(sizeof(line_sender));
    sender->sock_fd = sock_fd;
    sender->dest_info = dest_info;
    sender->state = line_sender_state_connected;
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

bool line_sender_utf8_init(
    line_sender_utf8* str,
    size_t len,
    const char* buf,
    line_sender_error** err_out)
{
    utf8_error u8err;
    if (!utf8_check(len, buf, &u8err))
    {
        size_t buf_descr_len = 0;
        char* buf_descr = describe_buf(len, buf, &buf_descr_len);
        if (u8err.need_more)
        {
            *err_out = err_printf(
                NULL,
                line_sender_error_invalid_utf8,
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
                NULL,
                line_sender_error_invalid_utf8,
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
    str->len = len;
    str->buf = buf;
    return true;
}

bool line_sender_name_init(
    line_sender_name* name,
    size_t len,
    const char* buf,
    line_sender_error** err_out)
{
    if (!len)
    {
        *err_out = err_printf(
            NULL,
            line_sender_error_invalid_name,
            "table, symbol and column names must have a non-zero length.");
        return false;
    }

    line_sender_utf8 str;
    if (!line_sender_utf8_init(&str, len, buf, err_out))
        return false;

    for (size_t index = 0; index < len; ++index)
    {
        const char c = buf[index];
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
                    size_t buf_descr_len = 0;
                    char* buf_descr = describe_buf(len, buf, &buf_descr_len);
                    char escaped[5];
                    const size_t escaped_len = escape_char(escaped, c);
                    *err_out = err_printf(
                        NULL,
                        line_sender_error_invalid_name,
                        "Bad string \"%.*s\": "
                        "table, symbol and column names can't contain a '%.*s' "
                        "character, which was found at byte position "
                        "%" PRI_SIZET ".",
                        (int)buf_descr_len,
                        buf_descr,
                        (int)escaped_len,
                        escaped,
                        index);
                    free(buf_descr);
                }
                return false;
            default:
                break;
        }

        // Reject unicode char 'ZERO WIDTH NO-BREAK SPACE', aka UTF-8 BOM
        // if it appears anywhere in the string.
        if ((c == '\xef') &&
            ((index + 2) < len) &&
            (buf[index + 1] == '\xbb') &&
            (buf[index + 2] == '\xbf'))
        {
            size_t buf_descr_len = 0;
            char* buf_descr = describe_buf(len, buf, &buf_descr_len);
            *err_out = err_printf(
                NULL,
                line_sender_error_invalid_name,
                "Bad string \"%.*s\": "
                "table, symbol and column names can't contain a UTF-8 BOM "
                "character, which was found at byte position "
                "%" PRI_SIZET ".",
                (int)buf_descr_len,
                buf_descr,
                index);
            free(buf_descr);
            return false;
        }
    }
    name->len = len;
    name->buf = buf;
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
    static void FN_NAME(mem_writer* writer, size_t len, const char* s)         \
    {                                                                          \
        size_t to_escape = 0;                                                  \
        for (size_t index = 0; index < len; ++index)                           \
            if (CHECK_ESCAPE_FN(s[index]))                                     \
                ++to_escape;                                                   \
        QUOTING_FN;                                                            \
        if (!to_escape)                                                        \
        {                                                                      \
            mem_writer_str(writer, len, s);                                    \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            char* buf = mem_writer_book(writer, len + to_escape);              \
            const char* init_buf = buf;                                        \
            for (size_t index = 0; index < len; ++index)                       \
            {                                                                  \
                const char c = s[index];                                       \
                if (must_escape_unquoted(c))                                   \
                    *buf++ = '\\';                                             \
                *buf++ = c;                                                    \
            }                                                                  \
            mem_writer_advance(writer, (size_t)(buf - init_buf));              \
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
    (mem_writer_char(writer, '"')))

bool line_sender_table(
    line_sender* sender,
    line_sender_name name,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_table, err_out))
        return false;

    write_escaped_unquoted(&sender->writer, name.len, name.buf);

    sender->state = line_sender_state_table_written;
    return true;
}

bool line_sender_symbol(
    line_sender* sender,
    line_sender_name name,
    line_sender_utf8 value,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_symbol, err_out))
        return false;

    mem_writer_char(&sender->writer, ',');
    write_escaped_unquoted(&sender->writer, name.len, name.buf);
    mem_writer_char(&sender->writer, '=');
    write_escaped_unquoted(&sender->writer, value.len, value.buf);

    sender->state = line_sender_state_symbol_written;
    return true;
}

static inline bool write_column_key(
    line_sender* sender,
    line_sender_name name,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_column, err_out))
        return false;

    const char separator =
        (sender->state & line_sender_op_symbol)
            ? ' '
            : ',';
    mem_writer_char(&sender->writer, separator);
    write_escaped_unquoted(&sender->writer, name.len, name.buf);
    mem_writer_char(&sender->writer, '=');
    sender->state = line_sender_state_column_written;
    return true;
}

bool line_sender_column_bool(
    line_sender* sender,
    line_sender_name name,
    bool value,
    line_sender_error** err_out)
{
    if (!write_column_key(sender, name, err_out))
        return false;
    mem_writer_char(&sender->writer, value ? 't' : 'f');
    return true;
}

bool line_sender_column_i64(
    line_sender* sender,
    line_sender_name name,
    int64_t value,
    line_sender_error** err_out)
{
    if (!write_column_key(sender, name, err_out))
        return false;
    mem_writer_i64(&sender->writer, value);
    mem_writer_char(&sender->writer, 'i');
    return true;
}

bool line_sender_column_f64(
    line_sender* sender,
    line_sender_name name,
    double value,
    line_sender_error** err_out)
{
    if (!write_column_key(sender, name, err_out))
        return false;
    mem_writer_f64(&sender->writer, value);
    return true;
}

bool line_sender_column_str(
    line_sender* sender,
    line_sender_name name,
    line_sender_utf8 value,
    line_sender_error** err_out)
{
    if (!write_column_key(sender, name, err_out))
        return false;
    write_escaped_quoted(&sender->writer, value.len, value.buf);
    return true;
}

static inline void update_last_line_start(line_sender* sender)
{
    sender->last_line_start = line_sender_pending_size(sender);
}

bool line_sender_at(
    line_sender* sender,
    int64_t epoch_nanos,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_at, err_out))
        return false;
    mem_writer* writer = &sender->writer;
    mem_writer_char(writer, ' ');
    mem_writer_i64(writer, epoch_nanos);
    mem_writer_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = line_sender_state_may_flush_or_table;
    return true;
}

bool line_sender_at_now(
    line_sender* sender,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_at, err_out))
        return false;
    mem_writer_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = line_sender_state_may_flush_or_table;
    return true;
}

size_t line_sender_pending_size(const line_sender* sender)
{
    return (sender->state != line_sender_state_moribund)
        ? mem_writer_len(&sender->writer)
        : 0;
}

static inline bool send_all(
    const line_sender* sender,
    sock_len_t len,
    const char* buf)
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

bool line_sender_flush(
    line_sender* sender,
    line_sender_error** err_out)
{
    if (!check_state(&sender->state, line_sender_op_flush, err_out))
        return false;

    size_t len = 0;
    const char* buf = mem_writer_peek(&sender->writer, &len);

    const bool send_ok = send_all(sender, (sock_len_t)len, buf);
    if (!send_ok)
    {
        const errno_t errnum = get_last_sock_err();
        char* err_descr = sock_err_str(errnum);
        *err_out = err_printf(
            &sender->state,
            line_sender_error_socket_error,
            "Could not flush buffered messages: %s.",
            err_descr);
        sock_err_str_free(err_descr);
        return false;
    }

    mem_writer_rewind(&sender->writer);
    sender->state = line_sender_state_connected;
    return true;
}

bool line_sender_must_close(const line_sender* sender)
{
    return sender->state == line_sender_state_moribund;
}

void line_sender_close(line_sender* sender)
{
    mem_writer_close(&sender->writer);
    CLOSESOCKET(sender->sock_fd);
    freeaddrinfo(sender->dest_info);
    free(sender);
#if defined(PLATFORM_WINDOWS)
    release_winsock();
#endif
}
