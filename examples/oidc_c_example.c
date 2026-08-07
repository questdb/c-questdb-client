#include <questdb/oidc.h>

#include <stdio.h>

static void oidc_event(void* user_data, const questdb_oidc_event* event)
{
    (void)user_data;
    if (event->kind == QUESTDB_OIDC_EVENT_PROMPT)
    {
        /* Prompt fields are display-sanitized. Only browser_target is vetted
         * for opening or turning into a clickable link. */
        fprintf(
            stderr,
            "Open %.*s and enter code %.*s\n",
            (int)event->verification_uri_len,
            event->verification_uri,
            (int)event->user_code_len,
            event->user_code);
    }
}

int main(void)
{
    questdb_error* error = NULL;
    questdb_oidc_builder* builder = questdb_oidc_builder_from_questdb(
        "https://questdb.example.com:9000",
        sizeof("https://questdb.example.com:9000") - 1,
        &error);
    questdb_oidc_auth* auth = NULL;
    line_sender_opts* options = NULL;
    line_sender* sender = NULL;
    if (!builder)
        goto fail;
    /* Credentials stay in memory. File persistence is an explicit opt-in that
     * stores tokens as unencrypted JSON; see questdb/oidc.h. */
    if (!questdb_oidc_builder_event_handler(
            builder, oidc_event, NULL, NULL, &error))
        goto fail;
    auth = questdb_oidc_builder_build(builder, &error);
    if (!auth)
        goto fail;

    /* Keep interactive UI on this thread. Later refreshes are automatic. */
    if (!questdb_oidc_auth_sign_in(auth, &error))
        goto fail;

    options = line_sender_opts_from_conf(
        QDB_UTF8_LITERAL("https::addr=questdb.example.com:9000;"), &error);
    if (!options || !line_sender_opts_oidc_auth(options, auth, &error))
        goto fail;
    sender = line_sender_build(options, &error);
    if (!sender)
        goto fail;

    line_sender_close(sender);
    line_sender_opts_free(options);
    questdb_oidc_auth_free(auth);
    questdb_oidc_builder_free(builder);
    return 0;

fail:
    if (error)
    {
        size_t message_len = 0;
        const char* message = questdb_error_msg(error, &message_len);
        fprintf(stderr, "OIDC example failed: %.*s\n", (int)message_len, message);
        questdb_oidc_error_view details = {0};
        details.struct_size = sizeof details;
        if (questdb_error_oidc_get_view(error, &details) && details.has_retry_after)
            fprintf(
                stderr,
                "Identity provider requested a retry after %llu seconds\n",
                (unsigned long long)details.retry_after_seconds);
    }
    questdb_error_free(error);
    line_sender_close(sender);
    line_sender_opts_free(options);
    questdb_oidc_auth_free(auth);
    questdb_oidc_builder_free(builder);
    return 1;
}
