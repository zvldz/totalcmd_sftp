#include "global.h"
#include <windows.h>
#include <string>
#include "SftpInternal.h"

bool PromptLooksLikePasswordRequest(const char* promptTextLower) noexcept
{
    if (!promptTextLower || !promptTextLower[0])
        return false;
    // Must contain "pass".
    if (!strstr(promptTextLower, "pass"))
        return false;
    // One-time codes: "PASSCODE" (RSA SecurID, Duo), OATH, tokens and
    // verification codes. A stored password sent there is disclosed for
    // nothing, and a code kept as the password is replayed on reconnect.
    for (const char* otp : { "passcode", "oath", "one time", "one-time", "otp",
                             "token", "verification", "code:" }) {
        if (strstr(promptTextLower, otp))
            return false;
    }
    return true;
}

StoredSecret SplitStoredSecret(const std::string& stored)
{
    StoredSecret out;
    if (stored.size() >= 2 && stored.front() == '"' && stored.back() == '"') {
        const size_t sep = stored.find("\",\"");
        // The passphrase runs from after the separator up to the closing quote.
        if (sep >= 1 && sep != std::string::npos && sep + 3 <= stored.size() - 1) {
            out.accountPassword = stored.substr(1, sep - 1);
            out.keyPassphrase   = stored.substr(sep + 3, stored.size() - sep - 4);
            out.labelled        = true;
            return out;
        }
    }
    // Nothing labels the two halves of a plain string, so it stands for
    // whichever secret is asked for: a profile carrying only a passphrase is
    // as common as one carrying only a password. Trying it as a passphrase
    // costs nothing — that use never leaves the machine — while the quoted
    // form above is what states which secret is which. Once it is seen to
    // open the key, authentication stops offering it as the password.
    out.accountPassword = stored;
    out.keyPassphrase   = stored;
    return out;
}
