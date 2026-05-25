################################################################################
##     ___                  _   ____  ____
##    / _ \ _   _  ___  ___| |_|  _ \| __ )
##   | | | | | | |/ _ \/ __| __| | | |  _ \
##   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
##    \__\_\\__,_|\___||___/\__|____/|____/
##
##  Copyright (c) 2014-2019 Appsicle
##  Copyright (c) 2019-2024 QuestDB
##
##  Licensed under the Apache License, Version 2.0 (the "License");
##  you may not use this file except in compliance with the License.
##  You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
##  Unless required by applicable law or agreed to in writing, software
##  distributed under the License is distributed on an "AS IS" BASIS,
##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##  See the License for the specific language governing permissions and
##  limitations under the License.
##
################################################################################

from libc.stdint cimport int64_t, uint16_t, uint64_t, uint8_t, uint32_t, int32_t

cdef extern from "stdbool.h":
    ctypedef unsigned char cbool "bool"

cdef extern from "questdb/ingress/line_sender.h":
    cdef struct line_sender_error:
        pass

    cdef enum line_sender_error_code:
        line_sender_error_could_not_resolve_addr,
        line_sender_error_invalid_api_call,
        line_sender_error_socket_error,
        line_sender_error_invalid_utf8,
        line_sender_error_invalid_name,
        line_sender_error_invalid_timestamp,
        line_sender_error_auth_error,
        line_sender_error_tls_error,
        line_sender_error_http_not_supported,
        line_sender_error_server_flush_error,
        line_sender_error_config_error,
        line_sender_error_array_error,
        line_sender_error_protocol_version_error,
        line_sender_error_invalid_decimal,
        line_sender_error_server_rejection

    cdef enum line_sender_protocol:
        line_sender_protocol_tcp,
        line_sender_protocol_tcps,
        line_sender_protocol_http,
        line_sender_protocol_https,
        line_sender_protocol_qwpudp,
        line_sender_protocol_qwpws,
        line_sender_protocol_qwpwss,
        line_sender_protocol_unknown,

    cdef enum line_sender_protocol_version:
        line_sender_protocol_version_1 = 1,
        line_sender_protocol_version_2 = 2,
        line_sender_protocol_version_3 = 3,

    cdef enum line_sender_ca:
        line_sender_ca_webpki_roots,
        line_sender_ca_os_roots,
        line_sender_ca_webpki_and_os_roots,
        line_sender_ca_pem_file,

    cdef enum line_sender_qwpws_progress:
        LINE_SENDER_QWPWS_PROGRESS_BACKGROUND,
        LINE_SENDER_QWPWS_PROGRESS_MANUAL,

    cdef struct line_sender_qwpws_fsn:
        cbool has_value
        uint64_t value

    cdef enum line_sender_qwpws_error_category:
        LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH,
        LINE_SENDER_QWPWS_ERROR_PARSE_ERROR,
        LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR,
        LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR,
        LINE_SENDER_QWPWS_ERROR_WRITE_ERROR,
        LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION,
        LINE_SENDER_QWPWS_ERROR_UNKNOWN,

    cdef enum line_sender_qwpws_error_policy:
        LINE_SENDER_QWPWS_ERROR_DROP_AND_CONTINUE,
        LINE_SENDER_QWPWS_ERROR_HALT,

    cdef struct line_sender_qwpws_error:
        pass

    cdef struct line_sender_qwpws_error_view:
        line_sender_qwpws_error_category category
        line_sender_qwpws_error_policy applied_policy
        cbool has_status
        uint8_t status
        cbool has_message_sequence
        uint64_t message_sequence
        uint64_t from_fsn
        uint64_t to_fsn
        const char* message
        size_t message_len

    ctypedef void (*line_sender_qwpws_error_cb)(
        void* user_data,
        const line_sender_qwpws_error_view* event
        ) noexcept with gil

    line_sender_error_code line_sender_error_get_code(
        const line_sender_error* error
        ) noexcept nogil

    const char* line_sender_error_msg(
        const line_sender_error* error,
        size_t* len_out
        ) noexcept nogil

    void line_sender_error_free(
        line_sender_error* error
        ) noexcept nogil

    cdef struct line_sender_utf8:
        size_t len
        const char *buf

    bint line_sender_utf8_init(
        line_sender_utf8* string,
        size_t len,
        const char* buf,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_utf8 line_sender_utf8_assert(
        size_t len,
        const char* buf
        ) noexcept nogil

    cdef struct line_sender_table_name:
        size_t len
        const char* buf

    bint line_sender_table_name_init(
        line_sender_table_name* name,
        size_t len,
        const char* buf,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_table_name line_sender_table_name_assert(
        size_t len,
        const char* buf
        ) noexcept nogil

    cdef struct line_sender_column_name:
        size_t len
        const char* buf

    cdef struct line_sender_buffer_view:
        size_t len
        const uint8_t* buf

    bint line_sender_column_name_init(
        line_sender_column_name* name,
        size_t len,
        const char* buf,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_column_name line_sender_column_name_assert(
        size_t len,
        const char* buf
        ) noexcept nogil

    cdef struct line_sender_buffer:
        pass

    line_sender_buffer* line_sender_buffer_new(
        line_sender_protocol_version version,
        ) noexcept nogil

    line_sender_buffer* line_sender_buffer_with_max_name_len(
        line_sender_protocol_version version,
        size_t max_name_len
        ) noexcept nogil

    line_sender_buffer* line_sender_buffer_new_qwp(
        ) noexcept nogil

    line_sender_buffer* line_sender_buffer_new_qwp_with_max_name_len(
        size_t max_name_len
        ) noexcept nogil

    void line_sender_buffer_free(
        line_sender_buffer* buffer
        ) noexcept nogil

    line_sender_buffer* line_sender_buffer_clone(
        const line_sender_buffer* buffer
        ) noexcept nogil

    bint line_sender_buffer_reserve(
        line_sender_buffer* buffer,
        size_t additional,
        line_sender_error** err_out
        ) noexcept nogil

    size_t line_sender_buffer_capacity(
        const line_sender_buffer* buffer
        ) noexcept nogil

    bint line_sender_buffer_set_marker(
        line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_rewind_to_marker(
        line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    void line_sender_buffer_clear_marker(
        line_sender_buffer* buffer
        ) noexcept nogil

    void line_sender_buffer_clear(
        line_sender_buffer* buffer
        ) noexcept nogil

    size_t line_sender_buffer_size(
        const line_sender_buffer* buffer
        ) noexcept nogil

    size_t line_sender_buffer_row_count(
        const line_sender_buffer* buffer
        ) noexcept nogil

    bint line_sender_buffer_transactional(
        const line_sender_buffer* buffer
        ) noexcept nogil

    line_sender_buffer_view line_sender_buffer_peek(
        const line_sender_buffer* buffer
        ) noexcept nogil

    bint line_sender_buffer_table(
        line_sender_buffer* buffer,
        line_sender_table_name name,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_symbol(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        line_sender_utf8 value,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_bool(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        bint value,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_i64(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        int64_t value,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_f64(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        double value,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_str(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        line_sender_utf8 value,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_f64_arr_c_major(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        size_t rank,
        const size_t* shapes,
        const double* data,
        size_t data_len,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_f64_arr_byte_strides(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        size_t rank,
        const size_t* shapes,
        const ssize_t* strides,
        const double* data,
        size_t data_len,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_ts_nanos(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        int64_t nanos,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_ts_micros(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        int64_t micros,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_dec_str(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        const char *value,
        size_t value_len,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_column_dec(
        line_sender_buffer* buffer,
        line_sender_column_name name,
        const unsigned int scale,
        const uint8_t* data,
        size_t data_len,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_at_nanos(
        line_sender_buffer* buffer,
        int64_t epoch_nanos,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_at_micros(
        line_sender_buffer* buffer,
        int64_t epoch_micros,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_at_now(
        line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_buffer_check_can_flush(
        const line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    cdef struct line_sender:
        pass

    cdef struct line_sender_opts:
        pass

    line_sender_opts* line_sender_opts_from_conf(
        line_sender_utf8 conf,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_opts* line_sender_opts_from_env(
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_opts* line_sender_opts_new(
        line_sender_protocol protocol,
        line_sender_utf8 host,
        uint16_t port
        ) noexcept nogil

    line_sender_opts* line_sender_opts_new_service(
        line_sender_protocol protocol,
        line_sender_utf8 host,
        line_sender_utf8 port
        ) noexcept nogil

    bint line_sender_opts_bind_interface(
        line_sender_opts* opts,
        line_sender_utf8 bind_interface,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_max_datagram_size(
        line_sender_opts* opts,
        size_t max_datagram_size,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_multicast_ttl(
        line_sender_opts* opts,
        uint32_t multicast_ttl,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_qwpws_progress(
        line_sender_opts* opts,
        line_sender_qwpws_progress progress,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_qwpws_error_handler(
        line_sender_opts* opts,
        line_sender_qwpws_error_cb cb,
        void* user_data,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_username(
        line_sender_opts* opts,
        line_sender_utf8 username,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_password(
        line_sender_opts* opts,
        line_sender_utf8 password,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_token(
        line_sender_opts* opts,
        line_sender_utf8 token,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_token_x(
        line_sender_opts* opts,
        line_sender_utf8 token_x,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_token_y(
        line_sender_opts* opts,
        line_sender_utf8 token_y,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_protocol_version(
        line_sender_opts* opts,
        line_sender_protocol_version version,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_auth_timeout(
        line_sender_opts* opts,
        uint64_t millis,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_tls_verify(
        line_sender_opts* opts,
        bint verify,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_tls_ca(
        line_sender_opts* opts,
        line_sender_ca ca,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_tls_roots(
        line_sender_opts* opts,
        line_sender_utf8 path,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_tls_roots_password(
        line_sender_opts* opts,
        line_sender_utf8 password,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_max_buf_size(
        line_sender_opts* opts,
        size_t max_buf_size,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_max_name_len(
        line_sender_opts* opts,
        size_t max_name_len,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_retry_timeout(
        line_sender_opts* opts,
        uint64_t millis,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_retry_max_backoff(
        line_sender_opts* opts,
        uint64_t millis,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_request_min_throughput(
        line_sender_opts* opts,
        uint64_t bytes_per_sec,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_opts_request_timeout(
        line_sender_opts* opts,
        uint64_t millis,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_opts* line_sender_opts_clone(
        const line_sender_opts* opts
        ) noexcept nogil

    void line_sender_opts_free(
        line_sender_opts* opts
        ) noexcept nogil

    line_sender* line_sender_build(
        const line_sender_opts *opts,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender* line_sender_from_conf(
        line_sender_utf8 config,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender* line_sender_from_env(
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_protocol_version line_sender_get_protocol_version(
        const line_sender * sender
        ) noexcept nogil

    line_sender_protocol line_sender_get_protocol(
        const line_sender * sender
        ) noexcept nogil

    size_t line_sender_get_max_name_len(
        const line_sender * sender
        ) noexcept nogil

    line_sender_buffer* line_sender_buffer_new_for_sender(
        const line_sender * sender
        ) noexcept nogil

    bint line_sender_must_close(
        const line_sender* sender
        ) noexcept nogil

    void line_sender_close(
        line_sender* sender
        ) noexcept nogil

    bint line_sender_qwpws_flush_and_get_fsn(
        line_sender* sender,
        line_sender_buffer* buffer,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_flush_and_keep_and_get_fsn(
        line_sender* sender,
        const line_sender_buffer* buffer,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_drive_once(
        line_sender* sender,
        cbool* progressed_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_published_fsn(
        const line_sender* sender,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_acked_fsn(
        const line_sender* sender,
        line_sender_qwpws_fsn* fsn_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_await_acked_fsn(
        line_sender* sender,
        uint64_t fsn,
        uint64_t timeout_millis,
        cbool* reached_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_poll_error(
        line_sender* sender,
        line_sender_qwpws_error** error_out,
        line_sender_error** err_out
        ) noexcept nogil

    line_sender_qwpws_error_view line_sender_qwpws_error_get_view(
        const line_sender_qwpws_error* error
        ) noexcept nogil

    bint line_sender_error_qwpws_get_view(
        const line_sender_error* error,
        line_sender_qwpws_error_view* view_out
        ) noexcept nogil

    void line_sender_qwpws_error_free(
        line_sender_qwpws_error* error
        ) noexcept nogil

    bint line_sender_qwpws_errors_dropped(
        const line_sender* sender,
        uint64_t* dropped_out,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_qwpws_close_drain(
        line_sender* sender,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_flush(
        line_sender* sender,
        line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_flush_and_keep(
        line_sender *sender,
        const line_sender_buffer* buffer,
        line_sender_error** err_out
        ) noexcept nogil

    bint line_sender_flush_and_keep_with_flags(
        line_sender* sender,
        line_sender_buffer* buffer,
        bint transactional,
        line_sender_error** err_out
        ) noexcept nogil

    int64_t line_sender_now_nanos(
        ) noexcept nogil

    int64_t line_sender_now_micros(
        ) noexcept nogil


    # Extra private API, not exposed in header
    bint line_sender_opts_user_agent(
        line_sender_opts* opts,
        line_sender_utf8 user_agent,
        line_sender_error** err_out
        ) noexcept nogil
