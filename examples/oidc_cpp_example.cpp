#include <questdb/ingress/line_sender.hpp>

#include <iostream>

int main()
{
    try
    {
        auto auth =
            questdb::oidc::builder::from_questdb(
                "https://questdb.example.com:9000")
                .event_handler([](const questdb::oidc::event_view& event) {
                    if (event.kind() != questdb::oidc::event_kind::prompt)
                        return;
                    // Display fields are sanitized, so they are safe to print
                    // but not to act on: verification_uri() may still be a URL
                    // the client refused to vet. browser_target() is the only
                    // vetted one, and it is empty exactly when nothing was
                    // safe to offer -- so only it may be presented as
                    // something to open, especially since many terminals
                    // auto-linkify a printed URL.
                    const auto target = event.browser_target();
                    if (!target.empty())
                        std::cerr << "Open " << target << " and enter "
                                  << event.user_code() << " (valid for "
                                  << event.expires_in_seconds()
                                  << " seconds; polling every "
                                  << event.interval_seconds() << " seconds)\n";
                    else
                        std::cerr << "Enter " << event.user_code()
                                  << " at your identity provider's device page "
                                     "(valid for "
                                  << event.expires_in_seconds()
                                  << " seconds; polling every "
                                  << event.interval_seconds()
                                  << " seconds). No vetted browser target was "
                                     "supplied; for reference only, the "
                                     "unverified page was reported as ["
                                  << event.verification_uri() << "]\n";
                })
                .build();

        // Credentials stay in memory. File persistence is an explicit opt-in
        // that stores tokens as unencrypted JSON; see questdb/oidc.hpp.

        // Run interactive sign-in on the main thread. Sender refreshes use the
        // same auth state automatically on every connect and reconnect.
        auth.sign_in();
        auto options = questdb::ingress::opts::from_conf(
            "https::addr=questdb.example.com:9000;");
        options.oidc_auth(auth);
        questdb::ingress::line_sender sender{options};
        return 0;
    }
    catch (const questdb::ingress::line_sender_error& error)
    {
        if (const auto& oidc = error.oidc_diagnostic())
            std::cerr << "Sender OIDC failure: " << oidc->what() << '\n';
        else
            std::cerr << "Sender failure: " << error.what() << '\n';
        return 1;
    }
    catch (const questdb::oidc::error& error)
    {
        std::cerr << "OIDC failure: " << error.what() << '\n';
        return 1;
    }
    catch (const questdb::error& error)
    {
        std::cerr << "QuestDB failure: " << error.what() << '\n';
        return 1;
    }
}
