#include <questdb/ingress/line_sender.hpp>

#include <iostream>

int main()
{
    try
    {
        auto auth = questdb::oidc::builder::from_questdb(
                        "https://questdb.example.com:9000")
                        .event_handler([](const questdb::oidc::event_view& event) {
                            if (event.kind() == questdb::oidc::event_kind::prompt)
                                // Display fields are sanitized. Use
                                // event.browser_target() for a clickable URL.
                                std::cerr << "Open " << event.verification_uri()
                                          << " and enter " << event.user_code()
                                          << '\n';
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
