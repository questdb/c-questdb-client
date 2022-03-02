#if __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <questdb/linesender.h>

#include "memwriter.h"
#include "utf8.h"
#include "aborting_malloc.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

_Static_assert((int)SOCK_STREAM == (int)linesender_tcp, "TCP enum matching");
_Static_assert((int)SOCK_DGRAM == (int)linesender_udp, "UDP enum matching");

// One-shot malloc and checked initialisation of all struct fields.
#define CONSTRUCT(T, ...)            \
  memcpy(aborting_malloc(sizeof(T)), \
         &(T const){ __VA_ARGS__ },  \
         sizeof(T))

static const size_t max_udp_packet_size = 64000;

typedef enum linesender_op
{
    linesender_op_metric = 1,
    linesender_op_tag = 1 << 1,
    linesender_op_field = 1 << 2,
    linesender_op_end_line = 1 << 3,
    linesender_op_flush = 1 << 4
} linesender_op;

static inline const char* linesender_op_str(linesender_op op)
{
    switch (op)
    {
        case linesender_op_metric:
            return "metric";
        case linesender_op_tag:
            return "tag";
        case linesender_op_field:
            return "field";
        case linesender_op_end_line:
            return "end_line";
        case linesender_op_flush:
            return "flush";
    }
    __builtin_unreachable();
}

// We encode the state we're in as a bitmask of allowable follow-up API calls.
typedef enum linesender_state
{
    linesender_state_connected =
        linesender_op_metric,
    linesender_state_metric_or_tag_written =
        linesender_op_tag | linesender_op_field,
    linesender_state_next_field_or_end =
        linesender_op_field | linesender_op_end_line,
    linesender_state_may_flush_or_metric =
        linesender_op_flush | linesender_op_metric,
    linesender_state_moribund = 0,
} linesender_state;

static inline const char* linesender_state_next_op_descr(linesender_state state)
{
    switch (state)
    {
        case linesender_state_connected:
            return "should have called `metric` instead";
        case linesender_state_metric_or_tag_written:
            return "should have called `tag` or `field` instead";
        case linesender_state_next_field_or_end:
            return "should have called `field` or `end_line` instead";
        case linesender_state_may_flush_or_metric:
            return "should have called `flush` or `metric` instead";
        case linesender_state_moribund:
            return "unrecoverable state due to previous error";
    }
    __builtin_unreachable();
}

struct linesender_error
{
    int errnum;
    size_t len;
    char* msg;
};

static linesender_error* err_printf(
    linesender_state* state,
    int errnum,
    const char* fmt,
    ...) __attribute__ ((format (printf, 3, 4)));

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
    return CONSTRUCT(linesender_error, errnum, len, msg);
}

/** Thread-safe variant of `strerror` which mallocs. Follow-up with `free`. */
static char* strerror_m(int errnum)
{
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
        ? max_len - 3  // 3 here for trailing `...`
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
    linesender_transport transport,
    const char* host,
    const char* port,
    linesender_error** err_out)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    // TODO: Review suitability for intended use case.
    // IPv4 Address resolution only at this point, no IPv6.
    // This is for feature parity with the Java implementation.
    // That said - barring testing - this should be the only code that
    // prevents the sender to work with both IPv4 and IPv6.
    hints.ai_family = AF_INET;
    hints.ai_socktype = transport;  // matches SOCK_STREAM or SOCK_DGRAM
    struct addrinfo* addr = NULL;
    int gai_err_code = getaddrinfo(host, port, &hints, &addr);
    if (gai_err_code)
    {
        size_t host_descr_len = 0;
        char* host_descr = describe_buf(strlen(host), host, &host_descr_len);
        if (port)
        {
            size_t port_descr_len = 0;
            char* port_descr = describe_buf(
                strlen(port), port, &port_descr_len);
            *err_out = err_printf(
                NULL,
                0,  // Note: gai_err_code != errno
                "Could not resolve \"%.*s:%.*s\": %s.",
                (int)host_descr_len,
                host_descr,
                (int)port_descr_len,
                port_descr,
                gai_strerror(gai_err_code));
            free(host_descr);
            free(port_descr);
        }
        else
        {
            *err_out = err_printf(
                NULL,
                0,  // Note: gai_err_code != errno
                "Could not resolve \"%.*s\": %s.",
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
    linesender_transport transport;
    int sock_fd;
    struct addrinfo* dest_info;
    linesender_state state;
    memwriter writer;
    size_t last_line_start;
};

linesender* linesender_connect(
    linesender_transport transport,
    const char* interface,
    const char* host,
    const char* port,
    int udp_multicast_ttl,
    linesender_error** err_out)
{
    switch (transport)
    {
        case linesender_tcp:
        case linesender_udp:
            break;
        default:
            *err_out = err_printf(
                NULL,
                0,
                "Bad transport value `%d`.",
                (int)transport);
            return NULL;
    }

    struct addrinfo* dest_info = NULL;
    struct addrinfo* if_info = NULL;
    int sock_fd = 0;

    dest_info = resolve_addr(
        transport, host, port, err_out);
    if (!dest_info)
        goto error_cleanup;

    if_info = resolve_addr(
        transport, interface, NULL, err_out);
    if (!if_info)
        goto error_cleanup;

    sock_fd = socket(
        dest_info->ai_family,
        dest_info->ai_socktype,
        dest_info->ai_protocol);
    if (sock_fd == -1)
    {
        char* err_descr = strerror_m(errno);
        *err_out = err_printf(
            NULL,
            errno,
            "Could not open TCP socket: %s.",
            err_descr);
        free(err_descr);
        goto error_cleanup;
    }

    if (fcntl(sock_fd, F_SETFD, FD_CLOEXEC) == -1)
    {
        char* err_descr = strerror_m(errno);
        *err_out = err_printf(
            NULL,
            errno,
            "Could not set FD_CLOEXEC on socket: %s.",
            err_descr);
        free(err_descr);
        goto error_cleanup;
    }

    if (transport == linesender_tcp)
    {
        // TODO: Review suitability for intended use case.
        // Compromise: We rely on the client to batch a sufficient number of
        // lines for decent throughput. This still allows for decent
        // timeliness.
        // This is bad if the client sends batch sizes of 1.
        // Maybe the answer here is to expose `nodelay` as an arg.
        int no_delay = 1;
        if (setsockopt(
            sock_fd,
            IPPROTO_TCP,
            TCP_NODELAY,
            (char *) &no_delay,
            sizeof(int)) == -1)
        {
            char* err_descr = strerror_m(errno);
            *err_out = err_printf(
                NULL,
                errno,
                "Could not set TCP_NODELAY: %s.",
                err_descr);
            free(err_descr);
            goto error_cleanup;
        }
    }
    else // if (transport == linesender_udp)
    {
        int set_res = 0;
        if (if_info->ai_family == AF_INET)  // IPv4
        {
            struct in_addr* ip_address =
                &((struct sockaddr_in*)if_info->ai_addr)->sin_addr;
            set_res = setsockopt(
                sock_fd,
                IPPROTO_IP,
                IP_MULTICAST_IF,
                ip_address,
                sizeof(struct in_addr));
        }
        else  // IPv6
        {
            struct in6_addr* ip_address =
                &((struct sockaddr_in6*)if_info->ai_addr)->sin6_addr;
            set_res = setsockopt(
                sock_fd,
                IPPROTO_IP,
                IPV6_MULTICAST_IF,
                ip_address,
                sizeof(struct in6_addr));
        }

        if (set_res == -1)
        {
            char* err_descr = strerror_m(errno);
            *err_out = err_printf(
                NULL,
                errno,
                "Could not set UDP sending-from address to `%s`: %s.",
                interface,
                err_descr);
            free(err_descr);
            goto error_cleanup;
        }

        if (if_info->ai_family == AF_INET)  // IPv4
        {
            set_res = setsockopt(
                sock_fd,
                IPPROTO_IP,
                IP_MULTICAST_TTL,
                &udp_multicast_ttl,
                sizeof(int));
        }
        else  // IPv6
        {
            set_res = setsockopt(
                sock_fd,
                IPPROTO_IP,
                IPV6_MULTICAST_HOPS,
                &udp_multicast_ttl,
                sizeof(int));
        }

        if (set_res == -1)
        {
            char* err_descr = strerror_m(errno);
            *err_out = err_printf(
                NULL,
                errno,
                "Could not set UDP TTL (max network hops) to `%d`: %s.",
                udp_multicast_ttl,
                err_descr);
            free(err_descr);
            goto error_cleanup;
        }
    }

    if (bind(sock_fd, if_info->ai_addr, dest_info->ai_addrlen) == -1)
    {
        char* err_descr = strerror_m(errno);
        *err_out = err_printf(
            NULL,
            errno,
            "Could not bind to interface address `%s`: %s.",
            interface,
            err_descr);
        free(err_descr);
        goto error_cleanup;
    }

    if (transport == linesender_tcp)
    {
        if (connect(sock_fd, dest_info->ai_addr, dest_info->ai_addrlen) == -1)
        {
            char* err_descr = strerror_m(errno);
            *err_out = err_printf(
                NULL,
                errno,
                "Could not connect to `%s:%s`: %s.",
                host,
                port,
                err_descr);
            free(err_descr);
            goto error_cleanup;
        }
    }

    freeaddrinfo(if_info);
    if_info = NULL;

    memwriter writer;
    memwriter_open(&writer, max_udp_packet_size);
    linesender* sender = CONSTRUCT(
        linesender,
        transport,
        sock_fd,
        dest_info,
        linesender_state_connected,
        writer,
        0);

    return sender;

error_cleanup:
    if (dest_info)
        freeaddrinfo(dest_info);
    if (if_info)
        freeaddrinfo(if_info);
    if (sock_fd)
        close(sock_fd);
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
                "Bad codepoint starting at byte index %zu.",
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
                "Illegal codepoint starting at byte index %zu.",
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
            "metric, tag and field names must have a non-zero length.");
        return false;
    }

    if (!check_utf8(state, len, name, err_out))
        return false;

    // TODO: Review for correctness.
    // Specifically, this logic is also used to validate metric names.
    // The validation logic is lifted from:
    // src/main/java/io/questdb/cairo/TableUtils.java's `isValidColumnName`.
    // Note that this differs from the InfluxDB spec since it allows names
    // that start with an underscore. See:
    // As per: https://docs.influxdata.com/influxdb/v2.0/reference/
    //   syntax/line-protocol/#naming-restrictions
    for (size_t index = 0; index < len; ++index)
    {
        const char c = name[index];
        switch (c)
        {
            // TODO: Review for correctness.
            // Do we really want to allow non-printable chars,
            // like \1\r \t \f etc in this context?
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
                        "metric, tag and field names can't contain a '%.*s' "
                        "character, which was found at byte position %zu.",
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
                "metric, tag and field names can't contain a UTF-8 BOM "
                "character, which was found at byte position %zu.",
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

bool linesender_metric(
    linesender* sender,
    size_t name_len,
    const char* name,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_metric, err_out))
        return false;
    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;

    write_escaped_unquoted(&sender->writer, name_len, name);

    sender->state = linesender_state_metric_or_tag_written;
    return true;
}

bool linesender_tag(
    linesender* sender,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_tag, err_out))
        return false;
    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;
    if (!check_utf8(&sender->state, value_len, value, err_out))
        return false;

    memwriter_char(&sender->writer, ',');
    write_escaped_unquoted(&sender->writer, name_len, name);
    memwriter_char(&sender->writer, '=');
    write_escaped_unquoted(&sender->writer, value_len, value);

    return true;
}

static inline bool write_field_key(
    linesender* sender,
    size_t name_len,
    const char* name,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_field, err_out))
        return false;

    if (!check_key_name(&sender->state, name_len, name, err_out))
        return false;

    const char separator =
        (sender->state == linesender_state_metric_or_tag_written)
            ? ' '
            : ',';
    memwriter_char(&sender->writer, separator);
    write_escaped_unquoted(&sender->writer, name_len, name);
    memwriter_char(&sender->writer, '=');
    sender->state = linesender_state_next_field_or_end;
    return true;
}

bool linesender_field_bool(
    linesender* sender,
    size_t name_len,
    const char* name,
    bool value,
    linesender_error** err_out)
{
    if (!write_field_key(sender, name_len, name, err_out))
        return false;
    memwriter_char(&sender->writer, value ? 't' : 'f');
    return true;
}

bool linesender_field_i64(
    linesender* sender,
    size_t name_len,
    const char* name,
    int64_t value,
    linesender_error** err_out)
{
    if (!write_field_key(sender, name_len, name, err_out))
        return false;
    memwriter_i64(&sender->writer, value);
    memwriter_char(&sender->writer, 'i');
    return true;
}

bool linesender_field_f64(
    linesender* sender,
    size_t name_len,
    const char* name,
    double value,
    linesender_error** err_out)
{
    if (!write_field_key(sender, name_len, name, err_out))
        return false;
    memwriter_f64(&sender->writer, value);
    return true;
}

bool linesender_field_str(
    linesender* sender,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out)
{
    if (!check_utf8(&sender->state, value_len, value, err_out))
        return false;
    if (!write_field_key(sender, name_len, name, err_out))
        return false;
    write_escaped_quoted(&sender->writer, value_len, value);
    return true;
}

static inline bool check_udp_max_line_len(
    linesender* sender,
    linesender_error** err_out)
{
    if (sender->transport == linesender_udp)
    {
        const size_t current_line_len =
            linesender_pending_size(sender) - sender->last_line_start;

        if (current_line_len > max_udp_packet_size)
        {
            *err_out = err_printf(
                &sender->state,
                0,
                "Current line is too long to be sent via UDP. "
                "Byte size %zu > %zu.",
                current_line_len,
                max_udp_packet_size);
            return false;
        }
    }
    return true;
}

static inline void update_last_line_start(linesender* sender)
{
    sender->last_line_start = linesender_pending_size(sender);
}

bool linesender_end_line_timestamp(
    linesender* sender,
    int64_t epoch_nanos,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_end_line, err_out))
        return false;
    if (!check_udp_max_line_len(sender, err_out))
        return false;
    memwriter* writer = &sender->writer;
    memwriter_char(writer, ' ');
    memwriter_i64(writer, epoch_nanos);
    memwriter_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = linesender_state_may_flush_or_metric;
    return true;
}

bool linesender_end_line(
    linesender* sender,
    linesender_error** err_out)
{
    if (!check_state(&sender->state, linesender_op_end_line, err_out))
        return false;
    if (!check_udp_max_line_len(sender, err_out))
        return false;
    memwriter_char(&sender->writer, '\n');
    update_last_line_start(sender);
    sender->state = linesender_state_may_flush_or_metric;
    return true;
}

size_t linesender_pending_size(linesender* sender)
{
    return (sender->state != linesender_state_moribund)
        ? memwriter_len(&sender->writer)
        : 0;
}

static inline bool send_tcp(linesender* sender, size_t len, const char* buf)
{
    while (len)
    {
        ssize_t send_res = send(
            sender->sock_fd,
            buf,
            len,
            0);
        if (send_res != -1)
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

static inline bool send_udp(linesender* sender, size_t len, const char* buf)
{
    while (len)
    {
        size_t boundary = (len < max_udp_packet_size)
            ? len
            : max_udp_packet_size;

        for (size_t index = boundary; index-- > 0;)
        {
            const char last = buf[index];

            // Note: No need to validate here.
            // `buf[index - 1]` can't fail due to state machine logic and UDP
            // max line len validation in `linesender_end_line_*` functions.
            const char penultimate = buf[index - 1];

            if ((last == '\n') && (penultimate != '\\'))
            {
                boundary = index + 1;
                break;
            }
        }

        ssize_t send_res = sendto(
            sender->sock_fd,
            buf,
            boundary,
            0,
            sender->dest_info->ai_addr,
            sender->dest_info->ai_addrlen);

        // We're sending UDP where `sendto` can't send less than a full packet.
        // As we've validated our buffer to be less than a maximum packet size,
        // we don't need to be concerned with partial writes.
        if (send_res != -1)
        {
            buf += boundary;
            len -= boundary;
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

    const bool send_ok = (sender->transport == linesender_tcp)
        ? send_tcp(sender, len, buf)
        : send_udp(sender, len, buf);
    if (!send_ok)
    {
        char* err_descr = strerror_m(errno);
        *err_out = err_printf(
            &sender->state,
            errno,
            "Could not flush buffered messages: %s.",
            err_descr);
        free(err_descr);
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
    close(sender->sock_fd);
    freeaddrinfo(sender->dest_info);
    free(sender);
}
