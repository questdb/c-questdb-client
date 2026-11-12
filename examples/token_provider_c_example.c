#include <questdb/token_provider.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Fetch a token however you like: Azure Identity, an OAuth2 client-credentials
 * or PKCE flow, a secrets vault. This stand-in reads one from the environment.
 * The refreshing provider calls it on its own thread, at about half of each
 * token's lifetime, so connects never wait for the identity platform. */
static void fetch_token(void* user_data, questdb_token_sink* sink)
{
    (void)user_data;
    const char* token = getenv("QDB_ACCESS_TOKEN");
    if (token == NULL || token[0] == '\0')
    {
        /* Missing configuration: retrying cannot help until it is fixed. A
         * network failure or a throttled request would be retryable. */
        static const char msg[] = "QDB_ACCESS_TOKEN is not set";
        questdb_token_sink_set_error(sink, false, -1, msg, sizeof(msg) - 1);
        return;
    }
    /* The platform reported a relative lifetime: compute the expiry from the
     * local time of receipt. */
    const int64_t lifetime_ms = 3600 * 1000;
    const int64_t now_ms = (int64_t)time(NULL) * 1000;
    questdb_token_sink_set_token(
        sink, token, strlen(token), now_ms + lifetime_ms, 0);
}

int main(void)
{
    questdb_error* error = NULL;
    line_sender_opts* options = NULL;
    line_sender* sender = NULL;

    questdb_refreshing_token_provider_options provider_options;
    questdb_refreshing_token_provider_options_init(
        &provider_options, sizeof provider_options);
    provider_options.name = "example";
    provider_options.name_len = strlen("example");
    questdb_token_provider* provider = questdb_refreshing_token_provider_new(
        fetch_token, NULL, NULL, &provider_options, &error);
    if (!provider)
        goto fail;
    /* Optional: wait for the first token before connecting. */
    if (!questdb_token_provider_await_ready(provider, 30000))
        fprintf(stderr, "no token yet; the sender will wait for one\n");

    options = line_sender_opts_from_conf(
        QDB_UTF8_LITERAL("wss::addr=questdb.example.com:9000;"), &error);
    if (!options || !line_sender_opts_token_provider(options, provider, &error))
        goto fail;
    sender = line_sender_build(options, &error);
    if (!sender)
        goto fail;

    line_sender_close(sender);
    line_sender_opts_free(options);
    /* Clients never close a provider: close it once none needs it. */
    questdb_token_provider_close(provider);
    questdb_token_provider_free(provider);
    return 0;

fail:
    if (error)
    {
        size_t message_len = 0;
        const char* message = questdb_error_msg(error, &message_len);
        fprintf(stderr, "Example failed: %.*s\n", (int)message_len, message);
        questdb_token_unavailable_view details;
        memset(&details, 0, sizeof details);
        details.struct_size = sizeof details;
        if (questdb_error_token_unavailable_get_view(error, &details))
            fprintf(
                stderr,
                "The token provider reported a %s failure\n",
                details.retryable ? "retryable" : "permanent");
    }
    questdb_error_free(error);
    line_sender_close(sender);
    line_sender_opts_free(options);
    questdb_token_provider_free(provider);
    return 1;
}
