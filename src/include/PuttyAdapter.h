#pragma once

#include "IExternalSessionSource.h"

namespace sftp {

// PuTTY session source.
//
// Standard channel: HKCU\Software\SimonTatham\PuTTY\Sessions — the
// registry key Simon Tatham's official PuTTY (and every drop-in fork
// that reuses it: ExtraPuTTY, PuTTY CAC, PuTTY portable that wraps
// official PuTTY) writes into. Tabbed-runners like mtPuTTY and
// SuperPuTTY also delegate storage here, so they are covered
// transparently.
//
// Detection: RegOpenKeyEx on the sessions root. A stripped install or
// portable-only setup yields ERROR_FILE_NOT_FOUND; anything else with
// the key present is treated as reachable, even if 0 sessions are
// stored inside.
//
// Field mapping (PuTTY registry value → tConnectSettings):
//   HostName          (REG_SZ)    → server (URL-decoded; :<port> appended when port != 22)
//   PortNumber        (REG_DWORD) → server ":<port>" suffix
//   UserName          (REG_SZ)    → user (URL-decoded)
//   PublicKeyFile     (REG_SZ)    → privkeyfile when the extension is .ppk / .pem,
//                                   pubkeyfile when the extension is .pub
//                                   (environment variables expanded)
//   AgentFwd / AuthAgent (REG_DWORD) → useagent = 1 when non-zero
//   LineCodePage = "UTF-8" (REG_SZ)  → utf8names = 1
//
// Password is intentionally not handled — PuTTY does not store one by
// design (Simon Tatham's stated position). Users get the standard
// interactive prompt on first connect after materialise, same as the
// SecureCRT adapter.
//
// Custom channel: PuTTY Portable — a single `putty.reg` file exported
// from PortableApps' PuTTYPortable\Data\settings\ (Windows Registry
// Editor Version 5.00, UTF-16 LE with BOM). Users pick the file via
// [Add custom location...]; the adapter parses the SessionSubKey
// entries and surfaces them alongside the standard registry channel.
class PuttyAdapter final : public IExternalSessionSource {
public:
    const char* SourceId()    const noexcept override { return "putty";   }
    const char* FolderName()  const noexcept override { return "[PuTTY]"; }

    bool DetectStandard() const noexcept override;

    EnumerationResult EnumerateStandard() override;
    EnumerationResult EnumerateCustomPath(const std::string& path) override;

    bool LoadSettings(const ExternalSessionEntry& entry,
                      pConnectSettings out) override;

    CustomPathPickerKind CustomPathPicker() const noexcept override
    { return CustomPathPickerKind::File; }

    const char* CustomPathFileFilter() const noexcept override
    {
        // NUL-separated Win32 filter: label\0pattern\0label\0pattern\0
        // Double-NUL termination happens automatically because the
        // string literal ends with an implicit '\0' after "*.*".
        return "PuTTY registry export (*.reg)\0*.reg\0All files (*.*)\0*.*\0";
    }
};

}  // namespace sftp
