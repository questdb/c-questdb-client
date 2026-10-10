#include <questdb/oidc.h>

#include <stdio.h>

static void oidc_event(void* user_data, const questdb_oidc_event* event)
{
    (void)user_data;
    if (event->kind == QUESTDB_OIDC_EVENT_PROMPT)
    {
        unsigned long long interval_seconds = 0;
        const char* browser_target = NULL;
        size_t browser_target_len = 0;
        if (event->struct_size >=
            offsetof(questdb_oidc_event, interval_seconds) +
                sizeof(event->interval_seconds))
            interval_seconds = (unsigned long long)event->interval_seconds;
        if (event->struct_size >=
            offsetof(questdb_oidc_event, browser_target_len) +
                sizeof(event->browser_target_len))
        {
            browser_target = event->browser_target;
            browser_target_len = event->browser_target_len;
        }
        /* Prompt fields are display-sanitized, which makes them safe to print
         * but NOT safe to act on: `verification_uri` may still be a URL the
         * client refused to vet (userinfo, a confusable IDNA host, plaintext
         * to a non-loopback IdP). Only `browser_target` is vetted for opening
         * or turning into a clickable link, and it is absent exactly when
         * there was nothing safe to offer -- so telling the user to open the
         * display URI would hand back the value the vetting just rejected.
         * Many terminals auto-linkify a printed URL, so keep the two cases
         * textually distinct. */
        if (browser_target != NULL && browser_target_len > 0)
            fprintf(
                stderr,
                "Open %.*s and enter code %.*s (valid for %.0f seconds; "
                "polling every %llu seconds)\n",
                (int)browser_target_len,
                browser_target,
                (int)event->user_code_len,
                event->user_code,
                event->expires_in_seconds,
                interval_seconds);
        else
            fprintf(
                stderr,
                "Enter code %.*s at your identity provider's device page "
                "(valid for %.0f seconds; polling every %llu seconds). No "
                "vetted browser target was supplied; for reference only, the "
                "unverified page was reported as [%.*s]\n",
                (int)event->user_code_len,
                event->user_code,
                event->expires_in_seconds,
                interval_seconds,
                (int)event->verification_uri_len,
                event->verification_uri);
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
        fprintf(
            stderr, "OIDC example failed: %.*s\n", (int)message_len, message);
        questdb_oidc_error_view details = {0};
        details.struct_size = sizeof details;
        if (questdb_error_oidc_get_view(error, &details) &&
            details.has_retry_after)
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
