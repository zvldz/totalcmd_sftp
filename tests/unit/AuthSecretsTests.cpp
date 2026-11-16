#include "Test.h"

#include "global.h"
#include <windows.h>
#include <string>
#include "SftpInternal.h"

TEST_CASE("auth: password prompts are told apart from one-time codes")
{
    for (const char* prompt : { "password: ", "password for tester@host: ",
                                "enter your password", "passwort: ", "(tester@host) password:" })
        CHECK(PromptLooksLikePasswordRequest(prompt));
    for (const char* prompt : { "enter passcode: ", "passcode or option (1-3): ",
                                "one-time password: ", "one time password:", "oath token password:",
                                "otp password: ", "verification code: ", "token password: ",
                                "pass code: ", "", "username: " })
        CHECK(!PromptLooksLikePasswordRequest(prompt));
}

TEST_CASE("auth: a stored secret names its halves only when quoted")
{
    const StoredSecret both = SplitStoredSecret("\"acc pw\",\"key pass\"");
    CHECK(both.labelled);
    CHECK(both.accountPassword == "acc pw");
    CHECK(both.keyPassphrase == "key pass");

    const StoredSecret plain = SplitStoredSecret("secret");
    CHECK(!plain.labelled);
    CHECK(plain.accountPassword == "secret");
    CHECK(plain.keyPassphrase == "secret");

    // A quoted string that is not the two-value form stays one secret.
    const StoredSecret quoted = SplitStoredSecret("\"just quoted\"");
    CHECK(!quoted.labelled);
    CHECK(quoted.accountPassword == "\"just quoted\"");

    const StoredSecret empty = SplitStoredSecret("");
    CHECK(!empty.labelled);
    CHECK(empty.accountPassword.empty());
}
