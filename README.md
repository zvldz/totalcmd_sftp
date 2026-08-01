# Secure FTP Plugin for Total Commander

> [!CAUTION]
> **2026-03-13 — Visual C++ Redistributable dependency removed**
>
> Previous builds reported *"Error loading plugin file! The plugin probably needs some DLLs missing"*
> on clean systems without Visual C++ Redistributable installed (`MSVCRT.dll` / `vcruntime140.dll`).
>
> Root cause: `argon2_a.lib` and `libssh2.lib` were compiled with `/MD` (dynamic CRT).
> Fixed: both libraries rebuilt from source with `/MT` — fully static C runtime.
> **The plugin requires no external DLLs or VC++ Redistributable.**

> [!IMPORTANT]
> **2026-03-21 — PHP Agent TAR batch download + sftp.php update required**
>
> Users running recent builds with the **TAR stream** option enabled may have experienced:
> - Silent batch download failures (0 files received) when downloading multiple files
> - HTTP 504 Gateway Timeout on OVH / home.pl when downloading large file sets
> - TAR upload failures for directory archives exceeding 4 GB
>
> All three are now fixed. **Upload the updated `sftp.php`** from the plugin directory to your server
> before using TAR batch download. See [PHP Agent Deployment](#php-agent-deployment) for instructions.

![SFTP Plugin](images/sftp01.jpg)

**Version 10.0.2.x** — Modern C++20 SFTP/SCP/PHP/LAN plugin for Total Commander x64 and x86.

Complete C-to-C++ rewrite of the original SFTP plugin by Christian Ghisler. Core transport, authentication, and session modules were re-engineered from scratch with a compatibility-first execution model, interface-driven backend abstraction, and hardened security primitives. The plugin selects the optimal transfer path at runtime — native SFTP, native SCP, shell chunk transfer via `cat`/`dd`/`base64`, PHP Agent over HTTP, or direct LAN Pair — depending on server constraints and deployment topology.

---

## Table of Contents

- [Feature Overview](#feature-overview)
- [Architecture](#architecture)
- [Transfer Protocols](#transfer-protocols)
- [Authentication System](#authentication-system)
- [Security and Password Storage](#security-and-password-storage)
- [Connection Management](#connection-management)
- [LAN Pair Transport](#lan-pair-transport)
- [PHP Agent and PHP Shell](#php-agent-and-php-shell)
  - [Command History](#command-history)
- [Remote File Operations](#remote-file-operations)
- [Shell Engineering Details](#shell-engineering-details)
- [Module Map](#module-map)
- [Source Tree](#source-tree)
- [Build System](#build-system)
- [System Requirements](#system-requirements)
- [Packaging and Installation](#packaging-and-installation)
- [PHP Agent Deployment](#php-agent-deployment)
- [Localization](#localization)
- [Roadmap](#roadmap)

---

## Feature Overview

### Transfer Protocols

| Protocol | Description |
|----------|-------------|
| **SFTP** | Primary transport. Full subsystem support, streaming transfers, resume on interrupted downloads and uploads. |
| **SCP (native)** | Faster than SFTP on many servers. Includes >2 GB file detection via 64-bit server check. |
| **Shell Fallback** | `cat` / `dd` / `base64` chunk pipeline for servers blocking SFTP subsystem and `scp`. Operates over a hidden interactive SSH channel. |
| **Jump Host (ProxyJump)** | Bastion-routed SSH via `direct-tcpip` tunneling. No external `ssh.exe` required. |
| **PHP Agent (HTTP)** | Standalone HTTP transfer mode backed by a single `sftp.php` file. Supports hosts with no SSH account or blocked subsystem. Directory uploads and batch file downloads transferred as a single TAR stream (opt-in via `php_tar` checkbox). TAR transfers replace thousands of individual HTTP requests with one POST/GET. |
| **PHP Shell (HTTP)** | Pseudo-terminal over HTTP via `SHELL_EXEC` in `sftp.php`. Persistent command history (Up/Down arrows, 128-entry ring buffer) stored in `%APPDATA%\GHISLER\shell_history.txt`. Maintains working-directory context across requests. |
| **LAN Pair** | Direct Windows-to-Windows pairing mode. Custom PAIR1 authentication protocol, LAN2 file-transfer command protocol, UDP broadcast peer discovery. |

### Authentication Methods

| Method | Notes |
|--------|-------|
| **Password** | Standard password auth. |
| **Keyboard-Interactive** | Includes automated password-change-request handling. |
| **PEM / OpenSSH** | Traditional private key formats, passed directly to libssh2. |
| **PPK v2 / v3 (native)** | Built-in PuTTY key file parser. No external tools. BCrypt + Argon2d/i/id + AES-256-CBC. |
| **Pageant** | SSH Agent integration. Auto-launch from `pageant.lnk` in the plugin directory. |
| **Fallback chain** | Automatic progression: Pageant → key file → keyboard-interactive → password. |

### Security Primitives

- Windows DPAPI (`CryptProtectData`) for password storage at the Windows account level.
- TC Master Password integration via `CryptProc` API with `!` sentinel.
- `SecureZeroMemory` on all sensitive buffers after use.
- PBKDF2-HMAC-SHA256 (120,000 iterations) and HMAC-SHA-256 challenge-response in LAN Pair auth.
- DPAPI-protected LAN Pair trust keys stored persistently per peer pair.
- `DllExceptionBarrier` — C++ exception firewall at every exported entry point; prevents any exception from crossing the ABI boundary into Total Commander (which would cause an immediate host crash).
- Legacy XOR passwords: read-only backward compatibility, never written for new profiles.

### Additional Capabilities

- **Folder-organised sessions** — group saved sessions into folders that appear in the plugin root listing. Folders are implicit (a folder exists while at least one session lives under it), so there is no extra setup step. F7 inside a folder creates a session there; F6 renames or moves a session across folders; F6 on a folder bulk-renames every session in it and keeps jump-host references intact. Backwards compatible with flat session profiles.
- Session import from PuTTY and WinSCP Windows Registry.
- Session import from PuTTY Portable: select the PuTTY Portable folder — the plugin finds `putty.reg` automatically (recursive search up to 4 levels deep).
- Session import from KiTTY Portable: select the KiTTYPortable root — the plugin finds the `Sessions` folder automatically (recursive search up to 4 levels deep); individual session files, only SSH sessions imported; stored passwords are automatically decrypted and saved to the plugin profile (DPAPI-protected).
- Proxy support: HTTP CONNECT, SOCKS4, SOCKS4a, SOCKS5 (with or without credentials).
- Dual-stack IPv4/IPv6 (`getaddrinfo`, `AF_INET6`).
- Host key fingerprint verification with first-connection warning and change alert.
- Remote checksum calculation without downloading: MD5, SHA1, SHA256, SHA512.
- Automatic UTF-8 filename detection via remote `locale` command.
- Automatic CRLF/LF conversion on text-mode transfers.
- Symlink tracking including `~` home directory shortcut protection.
- External `.lng` file localization — **15 languages** (EN/PL/RU/DE/FR/ES/IT/CS/HU/NL/PT-BR/RO/SK/UK/JA/ZH-CN) — dynamic dialog translation at runtime, auto-detected from TC `wincmd.ini`, language-aware control layout (`ArrangeInlineRow`)
- Dual-architecture distribution: x64 (`SFTPplug.wfx64`) and x86 (`SFTPplug.wfx`) in a single ZIP.
- Built-in CHM help (`sftpplug.chm`) opened from the plugin dialog Help button.
- Background transfer support (TC `BG_DOWNLOAD` / `BG_UPLOAD` flags).

---

## Architecture

### Layered Structure

```mermaid
flowchart TD
    A[TC WFX API] --> B[Entry Points]
    B --> C[SSH Layer]
    B --> D[Transfer Layer]
    B --> L[LAN Pair]
    C --> C1[Network/Proxy/Jump]
    C --> C2[Auth/Session]
    C --> C3[Dialog/Settings]
    D --> D1[SFTP/SCP/Shell]
    D --> D2[RemoteOps/Utils]
    D --> D3[PHP Agent/Shell]
    L --> L1[LanPair Session]
    C1 --> E[ISshBackend]
    C2 --> E
    D1 --> E
    D2 --> E
    E --> F[Libssh2]
    B --> G[IUserFeedback]
    G --> H[Win32 UI]
```

### ABI Exception Barrier

Total Commander is not built with the same compiler or exception-handling model as the plugin. Any C++ exception escaping an exported `Fs*` function crosses the ABI boundary and crashes the host process immediately.

`DllExceptionBarrier` (`DllExceptionBarrier.cpp`) is an RAII firewall applied at **every** exported entry point:

```cpp
int WINAPI FsGetFileW(LPCWSTR RemoteName, LPWSTR LocalName, ...) {
    sftp::DllExceptionBarrier barrier;
    return sftp::dll_invoke(barrier, FS_FILE_READERROR, [&]() -> int {
        // implementation — may throw freely
    });
}
```

When an exception is caught, the barrier:

1. Captures the call stack immediately via `CaptureStackBackTrace` + `SymFromAddr` / `SymGetLineFromAddr64` (Windows DbgHelp; SRWLOCK-serialised; lazy-initialized — zero overhead when no exception occurs).
2. Stores the live exception as `std::exception_ptr` (type preserved without RTTI; project builds with `/GR-`).
3. Re-throws locally to classify and extract `what()` text across `std::system_error` / `std::bad_alloc` / `std::exception` hierarchy.
4. Logs diagnostic + stack trace via `SFTP_LOG`.
5. Shows a `MessageBoxW` to the user (once per incident) with the full exception message and call stack.

Symbol names and file:line numbers resolve when the PDB sits next to `sftpplug.wfx`. Both Debug and Release configurations emit PDBs. Without a PDB, hex addresses are printed — still sufficient to identify the failing `Fs*` call chain.

`ShutdownSymbols()` is called from `DllMain DLL_PROCESS_DETACH` to release DbgHelp resources correctly, allowing re-initialization if TC reloads the DLL within the same process.

### ISshBackend Interface

All libssh2 calls are routed through pure-virtual interfaces: `ISshSession`, `ISshChannel`, `ISftpHandle`, `ISftpSession`, `ISshAgent`. This fully decouples business logic from the underlying SSH library.

```cpp
// ISftpHandle — wraps LIBSSH2_SFTP_HANDLE*
struct ISftpHandle {
    virtual ssize_t read(char* buf, size_t len) = 0;
    virtual ssize_t write(const char* buf, size_t len) = 0;
    virtual int readdir(char* buf, size_t blen,
                        char* longentry, size_t llen,
                        LIBSSH2_SFTP_ATTRIBUTES* attrs) = 0;
    virtual int fstat(LIBSSH2_SFTP_ATTRIBUTES* attrs, int setstat) = 0;
    virtual void seek(size_t offset) = 0;
    // ...
};
```

Consequences:
- Future backend migration (e.g., libssh) requires no changes to transfer or auth logic.
- Mock implementations allow unit-testing transfer paths without a real server.

### RAII and Memory Safety

- `std::unique_ptr<ISshSession>`, `std::unique_ptr<ISftpHandle>` throughout.
- `handle_util::AutoHandle<HANDLE>` for Windows file handles.
- `DataBlob` RAII wrapper for `CryptProtectData` / `CryptUnprotectData` output, calling `SecureZeroMemory` then `LocalFree` in destructor.
- `ConnectionGuard` RAII in `PluginEntryPoints.cpp` — ensures new connections are always closed and removed from the registry on any error path in `FsFindFirstW`, preventing resource leaks even when exceptions or early returns occur.
- No manual `new` / `delete` in any module written after the rewrite.

### IUserFeedback Pattern

`WindowsUserFeedback` implements a `IUserFeedback` interface that separates all `MessageBox` / progress-window calls from connection and transfer logic. This prevents UI calls on non-UI threads and makes background transfer mode stable.

### C++20 Feature Usage

| Feature | Used in |
|---------|---------|
| `std::span<const uint8_t>` | LanPair HMAC/PBKDF2, ShellFallbackTransfer |
| `std::string_view` | CoreUtils, LanPair, ProxyNegotiator, UnicodeHelpers |
| `std::optional<T>` | PasswordCrypto, LanPair, PpkConverter |
| `std::format` | PhpAgentClient |
| `constexpr` throughout | All modules |
| `noexcept` | LanPairSession public API, DllExceptionBarrier |
| `std::filesystem` | LanPair, build utilities |
| `std::thread`, `std::mutex`, `std::atomic` | LanPair discovery service |
| Designated initializers | Config structs |
| `int8_t` for tri-state flags | SftpTransfer autodetect |

---

## Connection Lifecycle

```mermaid
flowchart LR
    Start[Read TC Lang] --> UI[UI Language]
    Profile[Resolve Profile] --> T{Transport}
    T -->|LAN Pair| LP[Discovery]
    LP --> LS[Connect]
    LS --> Ops[Operations]
    T -->|PHP| PH[HTTP Auth]
    PH --> Ops
    T -->|SSH| S[Socket]
    S --> P{Proxy?}
    P -->|Yes| PN[Negotiate]
    P -->|No| J{Jump?}
    PN --> J
    J -->|Yes| JH[Auth]
    JH --> JT[Tunnel]
    JT --> I[Init SSH]
    J -->|No| I
    I --> F[Fingerprint]
    F --> A[Auth]
    A --> M{Submode}
    M -->|SFTP| SI[SFTP Init]
    M -->|SCP| SC[SCP Path]
    M -->|Shell| SH[Shell Path]
    SI --> Ops
    SC --> Ops
    SH --> Ops
```

Operational constraints enforced in every network loop:
- No unbounded EAGAIN spin.
- Per-phase timeout for connect, auth, and read.
- Deterministic cleanup on every failure path.

---

## Transfer Protocols

### SFTP (Primary)

Full SFTP subsystem support via libssh2. Streaming reads and writes with configurable chunk sizes. Transfer resume implemented correctly: uses `LIBSSH2_SFTP_ATTR_SIZE` flag in `fstat` to determine the actual remote file size before seeking — fixing a regression where resumes always restarted from offset 0.

### SCP (Native)

Dedicated `ScpTransfer.cpp` engine. Handles the SCP wire protocol without the SFTP subsystem. Faster than SFTP on many servers due to lower protocol overhead.

**>2 GB file support:**

| Step | Implementation |
|------|---------------|
| Server architecture check | Remote `file $(which scp)` to detect 64-bit binary |
| Transfer mode | Automatic adjustment for large files |
| Fallback | Shell transfer if SCP limit is detected at runtime |

Requires libssh2 ≥ 1.7.0 for 64-bit size field support.

### Shell Fallback (DD / Base64)

For servers where the SFTP subsystem is blocked and `scp` is unavailable. Uses a hidden interactive SSH shell channel.

```mermaid
sequenceDiagram
    participant L as Local
    participant P as Plugin
    participant C as SSH Channel
    participant S as Server
    L->>P: Read chunk
    P->>P: Base64 encode
    P->>C: Send payload
    C->>S: printf '%s' | base64 -d
    S-->>C: Output
    C-->>P: Parse
```

**Upload:** Split data into 1024-byte chunks → base64-encode → send via `printf '%s' | base64 -d` → server appends decoded bytes.

**Download:** Fast path via `cat`. Fallback to `base64 -w 0` when binary pipe is unreliable. Incremental decode (streaming, no full-file buffering).

Chunk size kept below 1024 bytes (1368 base64 characters) to stay within shell line-length limits on restricted hosts.

Base64 encoder is self-contained (`ShellB64Encode` / `ShellB64Decode` in `ShellFallbackTransfer.cpp`), with no external dependency.

### Jump Host (ProxyJump)

Handled in `JumpHostConnection.cpp`. Connects and authenticates to the bastion host, then opens a `direct-tcpip` channel to the final target. The full auth sequence (including PPK, Pageant, keyboard-interactive) runs on the jump host before the tunnel is established. No external `ssh.exe` binary involved.

**Pick existing session as jump host.** Next to the "Jump..." button on the F7 connection dialog there is a session-picker dropdown. Selecting an already-saved session uses its connection parameters (host, port, user, password, keys, agent) as the jump host — no need to retype them. The reference is stored as `jumpsessionref=<name>` in `sftpplug.ini` and resolved at connect time, so editing the referenced session propagates to every session that points at it (OpenSSH `ProxyJump` style). The "Jump..." button is disabled while a reference is active; pick `(none)` to switch back to manual configuration. Self-reference (picking the session being edited) is blocked at the UI level; chained or cyclic jump configurations are refused at connect time with a clear error.

### Remote Checksums

File integrity verification directly on the server:

| Algorithm | Shell commands tried |
|-----------|---------------------|
| MD5 | `md5sum` / `md5 -q` |
| SHA1 | `sha1sum` / `sha1 -q` |
| SHA256 | `sha256sum` / `shasum -a 256` |
| SHA512 | `sha512sum` / `shasum -a 512` |

---

## Authentication System

### Method Selection and Fallback

```mermaid
flowchart TD
    Start[Start Auth] --> P1{Pageant?}
    P1 -->|Yes| P2[Pageant]
    P1 -->|No| K1[Key File]
    P2 -->|OK| Done[Auth OK]
    P2 -->|Fail| K1
    K1 -->|OK| Done
    K1 -->|Fail| K2{Kbd-Int?}
    K2 -->|Yes| K3[Kbd-Int]
    K2 -->|No| PW[Password]
    K3 -->|OK| Done
    K3 -->|Fail| PW
    PW -->|OK| Done
    PW -->|Fail| Err[Auth Failed]
```

Fail-fast local validation before any network auth attempt:

| Condition | Behavior |
|-----------|----------|
| `privkeyfile` not set | Immediate local error — no fallback stall |
| Explicit `pubkeyfile` missing from disk | Immediate local error |
| Invalid PPK format | Precise error with MAC/KDF diagnostics |

This eliminates the minute-long UI freeze caused by impossible auth attempts in the original plugin.

### Native PPK v2 / v3 Decoder

Implemented in `PpkConverter.cpp`. Converts PuTTY Private Key files to traditional PEM format for libssh2 — no external tools, no `puttygen.exe`.

**PPK v3 specification coverage:**

| Component | Implementation |
|-----------|---------------|
| KDF | Argon2d / Argon2i / Argon2id — statically linked (argon2, /MT) |
| Encryption | AES-256-CBC |
| MAC | HMAC-SHA-256 over `(algorithm ‖ encryption ‖ comment ‖ public_blob ‖ private_blob_plain)` |
| MAC key source | Argon2 output bytes 48–79 (encrypted keys); empty string (unencrypted keys) |
| Key derivation | Windows BCrypt `BCRYPT_SHA256_ALGORITHM` with HMAC flag |
| Output | Traditional PEM, passed to `libssh2_userauth_publickey_frommemory` |

**PPK v2** uses SHA-1-based key derivation, also fully handled natively.

SSH wire format helpers (`AppendU32`, `AppendSshStr`, `ReadSshStr`) are implemented inline without any external parser library.

### Pageant Integration

Connects via named pipe to the running Pageant agent. If Pageant is not running and `pageant.lnk` exists in the plugin directory, the plugin launches it automatically before retrying agent auth.

---

## Security and Password Storage

### Storage Modes

```mermaid
graph LR
    A[Password] --> B{TC Master?}
    B -->|Yes| C[CryptProc]
    B -->|No| D[DPAPI]
    D --> E[CryptProtectData]
    C --> F[Encrypted INI]
    E --> F
```

| Mode | INI format | Description |
|------|-----------|-------------|
| TC Master Password | `password=!` | Delegated to TC `CryptProc` API |
| DPAPI | `password=dpapi:<base64>` | `CryptProtectData`, user-account scope |
| Explicit plaintext | `password=plain:<text>` | Opt-in only |
| Legacy XOR | `<decimal triplets>` | Read-only; written in 2000s versions |

### DPAPI Implementation

`DataBlob` RAII class in `PasswordCrypto.cpp`:

```cpp
class DataBlob {
    ~DataBlob() {
        if (blob_.pbData) {
            SecureZeroMemory(blob_.pbData, blob_.cbData);
            LocalFree(blob_.pbData);
        }
    }
    bool encrypt(const std::string& plain);       // CryptProtectData
    std::optional<std::string> decrypt() const;   // CryptUnprotectData
};
```

After decryption, the plaintext buffer is `SecureZeroMemory`-zeroed before `LocalFree`. Base64 encoding/decoding uses Windows `CryptBinaryToStringA` / `CryptStringToBinaryA`.

### ABI Boundary Protection

`DllExceptionBarrier` guards all exported `Fs*` functions. Any C++ exception — including `std::bad_alloc`, `std::system_error`, or third-party exceptions — is caught before it reaches Total Commander's call frame. The diagnostic (exception type, `what()` text, and resolved call stack) is logged and shown to the user in a `MessageBoxW`. TC continues running. See [ABI Exception Barrier](#abi-exception-barrier) in the Architecture section.

### Legacy XOR

The XOR key is hardcoded because:
1. XOR is obfuscation, not encryption — moving it would not improve security.
2. It is never used for writing new passwords.
3. Backward compatibility requires the same key to remain stable indefinitely.

Documented explicitly in source to prevent well-meaning refactors that would break existing user profiles.

---

## Connection Management

### Proxy Support

| Type | Auth |
|------|------|
| HTTP CONNECT | Basic (username:password) |
| SOCKS4 | None |
| SOCKS4a | None |
| SOCKS5 | None / username-password |

Implemented in `ProxyNegotiator.cpp`, isolated from the main connection path.

### Session Import

Sessions from other programs appear in an `[Imports]` folder in the plugin root, one subfolder per source. One adapter per source implements `IExternalSessionSource`; the enumerated lists are cached next to `sftpplug.ini` so they are available immediately at startup.

| Source | Auto-detected location | Custom location accepts |
|--------|------------------------|-------------------------|
| SecureCRT | `%APPDATA%\VanDyke\Config\Sessions\` | Any SecureCRT session tree |
| PuTTY | `HKCU\Software\SimonTatham\PuTTY\Sessions` | A `putty.reg` export |
| WinSCP | `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` | A portable `WinSCP.ini` |
| FileZilla | `%APPDATA%\FileZilla\sitemanager.xml` | Any `sitemanager.xml` |
| KiTTY | `%APPDATA%`, `%LOCALAPPDATA%`, `%USERPROFILE%` under `KiTTY\Sessions\`, or the path behind the `.kitty` file association | The `Sessions\` folder or the install root |

**Behaviour:**
- `Enter` connects using the settings read from the source; nothing is written to the plugin's own configuration
- `F5` materialises the session into `sftpplug.ini` as a regular saved entry — `Ctrl+A` first to take a whole source at once
- `[Refresh]` re-reads one source; `[Add custom location...]` and `[Manage custom locations]` handle portable installs
- Only sessions the plugin can serve are listed — non-SSH protocols, WinSCP workspaces and `Default Settings` templates are filtered out
- Folder hierarchies from the source are preserved as nested panel folders
- Passwords: imported for KiTTY and for FileZilla sites using base64 storage; PuTTY keeps none on disk; WinSCP and SecureCRT are left for the interactive prompt. Imported values are re-protected with DPAPI
- Key files carry over with environment variables resolved; `.ppk` v2/v3/ed25519 are converted natively
- Proxy, firewall and tunnel definitions are **not** carried over yet

### Host Key Verification

MD5 fingerprint stored in INI per server. First connection prompts acceptance. Changed key raises an explicit warning dialog. Both behaviors use the `IUserFeedback` interface so they work correctly in background transfer mode.

---

## LAN Pair Transport

Direct Windows-to-Windows file transfer without SSH. Uses a custom application-layer protocol stack over TCP/UDP on the local network.

### Discovery (UDP Broadcast)

`DiscoveryService` (in `LanPair.cpp`) runs a background thread broadcasting peer announcements and collecting incoming ones.

| Parameter | Default |
|-----------|---------|
| UDP broadcast port | 45845 |
| TCP pairing port | 45846 |
| Broadcast interval | 2000 ms |
| App tag | `KVCPAIR/1` |

`PeerAnnouncement` fields: `peerId`, `hostName`, `displayName`, `ip`, `tcpPort`, `role` (`Donor` / `Receiver` / `Dual`), `lastSeen`.

### PAIR1 Authentication Protocol

Challenge-response over the TCP socket established after discovery. Wire exchange:

```
Client → Server:  PAIR1 HELLO <peerId> <role> <clientNonceHex>
Server → Client:  PAIR1 CHALLENGE <serverNonceHex> <saltHex> <serverPeerId> <displayName> <role> <port>
Client → Server:  PAIR1 AUTH <proofHex>
Server → Client:  PAIR1 OK <serverProofHex>
             or:  PAIR1 OKTRUST <serverProofHex> <issuedTrustHex>
```

Key derivation for auth proof:

```
key    = PBKDF2-HMAC-SHA256(password, salt, 120 000 iterations, 32 bytes)
proof  = HMAC-SHA256(key, clientNonce ‖ serverNonce ‖ "client")
```

Both client and server verify each other's proof. On first successful connection with password, the server issues a trust token (`OKTRUST`). On subsequent connections, the stored DPAPI trust key is used instead of the password — TOFU (Trust On First Use) model.

### LAN Pair Roles

| Role | INI value | Behavior |
|------|-----------|----------|
| **Donor** | `lanpairrole=2` | Starts the local LAN Pair file server; waits for incoming Receiver connections; refuses to initiate outgoing connections. Use on the machine whose files will be accessed remotely. |
| **Receiver** | `lanpairrole=1` | Does not start a local file server; connects as client to the Donor. Use on the machine that will browse and transfer files. |
| **Auto** | `lanpairrole=0` | Starts the local file server and shows a guided 60-second pairing wizard. |

In the **Auto** wizard: **Yes** = connect immediately to the discovered peer (this machine acts as Receiver/client); **No** = stay as server/Donor; **Cancel** = stop server.

### TrustedInstaller Access

When the **Trusted Installer** checkbox (`lanparti=1`) is enabled:

- **As Donor (server):** incoming connections are served under TrustedInstaller impersonation — the remote Receiver can read, write, delete, and rename files owned by TrustedInstaller on this machine (e.g. files in `C:\Windows\`, Windows Update caches, `WindowsApps`).
- **As Receiver (client):** file transfers on this machine run under TI impersonation — allows downloading to TI-protected local directories and uploading from TI-protected local paths.

Impersonation is per-connection (server) or per-transfer (client) and is always reverted after use. Requires `SeDebugPrivilege` (elevated TC). The TrustedInstaller service is started automatically if not already running.

### DPAPI Trust Key Storage

`DpapiSecretStore` in `LanPair.h` persists trust keys in DPAPI-protected storage keyed by `"lanpair_trust_srv_<serverPeerId>__<clientPeerId>"`. Trust is per peer-pair, per Windows user account. Trust keys are saved with `CRYPTPROTECT_LOCAL_MACHINE` flag for compatibility with TrustedInstaller context. If an old key cannot be decrypted (e.g. after enabling TI), it is deleted automatically and re-pairing is triggered.

### LAN2 Command Protocol

After PAIR1, the authenticated TCP socket runs the LAN2 line-based command protocol for file operations:

```
Frame header: magic=0x4B564350 ("KVCP"), version=1, PairCommandType, reserved, payloadSize
```

`PairCommandType` values: `Handshake`, `ListRoots`, `ListDirectory`, `StartSend`, `StartReceive`, `DataChunk`, `Ack`, `Error`.

`LanPairSession` public API:

```cpp
static std::unique_ptr<LanPairSession> connect(...) noexcept;
bool listRoots(std::vector<std::string>& roots) noexcept;
bool listDirectory(const std::string& path, std::vector<DirEntry>& entries) noexcept;
bool getFile(const std::string& remotePath, LPCWSTR localPath, ...) noexcept;
bool putFile(LPCWSTR localPath, const std::string& remotePath, ...) noexcept;
bool mkdir(const std::string& path) noexcept;
bool remove(const std::string& path) noexcept;
bool rename(const std::string& oldPath, const std::string& newPath) noexcept;
void setTimeoutMin(int minutes) noexcept;
```

Session timeout configurable via `setTimeoutMin(int minutes)`. When a non-zero timeout is set, every `cmd()` call checks elapsed time via `std::chrono::steady_clock` and closes the session automatically when the limit is reached. All methods are `noexcept`.

---

## PHP Agent and PHP Shell

### PHP Agent (HTTP)

Single-file `sftp.php` deployed on the web server. The plugin communicates via WinHTTP (`winhttp.lib`), sending chunked `multipart/form-data` for uploads and receiving raw bytes for downloads.

Operations supported: `PROBE`, `LIST`, `GET`, `PUT`, `MKDIR`, `REMOVE`, `RENAME`, `CHMOD`, `STAT`, `TAR_STREAM`, `TAR_EXTRACT`, `TAR_PACK`, `SHELL_EXEC`.

#### TAR Streaming — Upload (TAR_EXTRACT) and Batch Download (TAR_PACK)

When the `php_tar` checkbox is enabled in the connection profile, all directory copies and batch file transfers use a single TAR HTTP round-trip instead of individual `PUT`/`GET` requests. This eliminates per-request overhead — critical on shared hosting (OVH, home.pl) where even small files cost full HTTP round-trip latency.

**Upload (TAR_EXTRACT)**

TC's `FsStatusInfo` `PUT_MULTI` / `PUT_MULTI_THREAD` session is used to collect all files. The plugin runs a first pass to compute the exact total size, then streams the complete POSIX ustar TAR in a single WinHTTP POST to `?op=TAR_EXTRACT`. The server script extracts files on-the-fly via a streaming parser (`tar_extract_stream`) — no temporary files created on the server. `Content-Length` is sent as a 64-bit header value (no 4 GB overflow). Regular `.tar` file uploads without `php_tar` enabled are unaffected.

**Batch Download (TAR_PACK)**

When TC signals a multi-file download (`FsStatusInfo GET_MULTI` / `GET_MULTI_THREAD`), each `FsGetFileW` call is intercepted and the remote path queued into `TarDownloadSession`. When the batch ends, a single POST to `?op=TAR_PACK` is sent with all remote paths (newline-separated). The server streams the ustar TAR directly to `php://output` with no buffering — no 504 Gateway Timeout even for large archives. The plugin parses the TAR stream on the fly, writing files as each entry arrives.

Both directions support **GNU LongLink** (`././@LongLink`, typeflag `L`) for paths longer than 99 characters. Files exceeding 8 589 934 591 bytes (POSIX ustar limit) are skipped cleanly without corrupting the rest of the archive.

```mermaid
sequenceDiagram
    participant TC as Total Commander
    participant P as Plugin
    participant S as sftp.php
    Note over TC,P: Batch download (GET_MULTI)
    TC->>P: FsStatusInfo GET_MULTI START
    P->>P: TarDownloadSessionBegin
    TC->>P: FsGetFileW (file 1)
    P->>P: TarDownloadSessionQueue
    TC->>P: FsGetFileW (file N)
    P->>P: TarDownloadSessionQueue
    TC->>P: FsStatusInfo GET_MULTI END
    P->>S: POST ?op=TAR_PACK
    S-->>P: ustar TAR stream
    P->>P: Parse TAR → write local files
```

```mermaid
sequenceDiagram
    participant TC as Total Commander
    participant P as Plugin
    participant S as sftp.php
    Note over TC,P: Batch upload (PUT_MULTI)
    TC->>P: FsStatusInfo PUT_MULTI START
    P->>P: TarUploadSessionBegin
    TC->>P: FsPutFileW (file 1..N)
    P->>P: TarUploadSessionQueue
    TC->>P: FsStatusInfo PUT_MULTI END
    P->>S: POST ?op=TAR_EXTRACT (TAR stream)
    S-->>P: { "extracted": N }
```

`AgentUrl` struct parsed from connection profile: `secure` (HTTPS), `host`, `port`, `object` path.

### PHP Shell (HTTP)

Uses the same `sftp.php` endpoint but routes commands through `SHELL_EXEC`. Maintains working-directory awareness across requests. Provides a pseudo-terminal experience for operational tasks on hosts with no SSH access.

#### Command History

The shell console maintains a **persistent** command history that survives session restarts and plugin reloads.

**Navigation**

| Key | Action |
|-----|--------|
| `↑` Up arrow | Recall previous command |
| `↓` Down arrow | Move forward through history (↓ after reaching the end clears the input line) |

**Storage location**

```
%APPDATA%\GHISLER\shell_history.txt
```

This is the same directory Total Commander uses for its own configuration, keeping all related data in one place. The file is a plain UTF-8 text file, one command per line, and can be opened or inspected in any text editor.

**Capacity — ring buffer**

The file holds a maximum of **128 entries**. When the 129th command is added, the oldest entry is dropped from the top. The file is always rewritten in full on every addition — at 128 short lines this is a negligible I/O cost and eliminates any possibility of stale data from a partial write.

**Duplicate suppression**

Consecutive identical commands are not added to history (equivalent to bash `HISTCONTROL=ignoredups`). Running the same command twice in a row records it only once.

**Clearing history**

History can be cleared from inside the shell console without leaving it:

```bash
history -c
```

or equivalently:

```bash
clear history
```

Both commands erase all entries from memory **and** delete `shell_history.txt` from disk immediately. The cursor resets to an empty state. This is equivalent to `history -c` in bash and is the recommended way to clear sensitive command traces (e.g. after typing a password inline).

> **Note:** `exit` and `logout` close the console window but do **not** clear history — existing entries are preserved for the next session.

**Power-loss and crash safety**

Each write uses an atomic two-step pattern:

1. The new content is written to a temporary file (`shell_history.txt.tmp`) in the same directory.
2. `MoveFileExA` with `MOVEFILE_REPLACE_EXISTING` renames the temp file over the real file.

On NTFS, a rename within the same volume is a single metadata operation. If power is lost or the process is killed between steps 1 and 2, the previous `shell_history.txt` remains intact — it is never truncated or partially overwritten. The worst-case outcome is a leftover `.tmp` file containing the most recent history, which can be renamed manually if needed.

### PHP Agent Deployment

> **Critical:** The `sftp.php` in the release package ships with **no password configured**. Uploading it before saving a session in the plugin will result in HTTP 503 on every connection attempt. Always follow the order below.

**Step 1 — Configure and save the session in Total Commander**

Open the plugin connection dialog (Net → Connect). Fill in:

| Field | Value |
|-------|-------|
| **Connect to** | Full URL to `sftp.php` on your server, e.g. `https://example.com/sftp.php` |
| **Transfer mode** | `PHP Agent (HTTP)` (or `PHP Shell (HTTP)`) |
| **Password** | Your chosen shared secret |
| **Session name** | Any label, e.g. `My Hosting` |

Click **Save**. The plugin writes a salted SHA-256 hash (`AGENT_PSK_SALT` + `AGENT_PSK_SHA256`) into its local copy of `sftp.php`. The password itself is never stored in the file.

**Step 2 — Upload the modified `sftp.php`**

Copy the local file (containing your hash) to the server:

```
...\Total Commander\plugins\wfx\SFTPplug\sftp.php  →  https://example.com/sftp.php
```

Use FTP, cPanel File Manager, or any other method. Do **not** upload the original from the download package — it has empty PSK fields.

**Step 3 — Verify the endpoint**

Open `https://example.com/sftp.php?op=PROBE` in a browser:

| Response | Meaning |
|----------|---------|
| HTTP 200 `{"status":"ok"}` | Ready — proceed to connect |
| HTTP 401 Unauthorized | Script running, awaiting auth — also OK |
| HTTP 503 Service Unavailable | PSK not configured — wrong file uploaded; repeat from Step 1 |
| HTTP 404 Not Found | Wrong URL or file not yet uploaded |

**Step 4 — Connect**

Select the saved session in Total Commander and connect.

**Security model**

| Location | Stored | Password exposed? |
|----------|--------|-------------------|
| `sftpplug.ini` (your PC) | Password encrypted with Windows DPAPI | No |
| `sftp.php` (server) | `AGENT_PSK_SALT` + SHA-256(salt + password) | No — one-way hash |
| Network (HTTPS) | HMAC-SHA256 signature + timestamp + nonce per request | No — signature only |

Even if someone reads `sftp.php` on the server, the original password cannot be recovered.

---

## Remote File Operations

All operations are available over SFTP, SCP, and PHP Agent modes (where applicable).

| Operation | SFTP | SCP/Shell | PHP Agent |
|-----------|------|-----------|-----------|
| Directory listing | Native SFTP readdir | `ls -la` + `__WFX_LIST_BEGIN__` / `__WFX_LIST_END__` markers | Agent `LIST` command |
| Download | Native, with resume | Shell / `cat` | Agent `GET` |
| Upload | Native, with resume | Shell / `dd` / base64 | Agent `PUT` |
| Rename / Move | SFTP `rename` | Remote `mv` | Agent `RENAME` |
| Delete file/tree | SFTP `unlink` / recursive | Remote `rm -rf` | Agent `REMOVE` |
| Create directory | SFTP `mkdir` | Remote `mkdir` | Agent `MKDIR` |
| Chmod | SFTP `setstat` | Remote `chmod` | Agent `CHMOD` |
| Set attributes (`FsSetAttrW`) | SFTP lstat → RMW write bits → setstat | — | — |
| Timestamps | SFTP `setstat` | Remote `touch` | — |
| Symlink resolution | SFTP `realpath` | Parsed from `ls -la` output | — |
| Remote checksum | Shell command | Shell command | — |
| File properties | SFTP `stat` | Shell `stat` | Agent `STAT` |

### Symlink and Tilde Handling

Symlinks are parsed from `ls -la` long-entry format and followed recursively. Special protection against downloading the literal string `~` as a file: the plugin detects this case, reconnects, and retries with the resolved home path.

---

## Shell Engineering Details

### Marker-Aware Directory Listing (SCP Mode)

Real SSH servers vary in shell behavior (prompts, echo, MOTD). The plugin injects unique markers to delimit directory output reliably:

| Marker | Purpose |
|--------|---------|
| `__WFX_LIST_BEGIN__` | Start of `ls -la` output |
| `__WFX_LIST_END__` | End of `ls -la` output |
| `echo $?` | Exit code detection after command |

Defensive buffer filtering discards echoed commands, prompts, and MOTD lines before parsing.

### Restricted Server Handling

| Scenario | Mitigation |
|----------|-----------|
| SFTP subsystem blocked | Fall through to SCP, then shell fallback |
| `scp` not available | Shell chunk transfer via `cat` / `dd` / base64 |
| Noisy shell prompts | Buffer filtering with marker anchoring |
| Delayed output (slow server) | Staggered read timeouts per stage |
| No 64-bit `scp` (>2 GB) | Automatic detection, fallback to shell transfer |

### UTF-8 Detection

Remote `locale` command output is parsed to determine the server's character encoding. If UTF-8 is detected, filename conversion uses the Unicode helpers in `UnicodeHelpers.cpp` / `UtfConversion.cpp`. Otherwise, system code page conversion is applied.

---

## Module Map

| Module | Responsibility | Notes |
|--------|---------------|-------|
| `PluginEntryPoints.cpp` | TC WFX API entry points (`FsFindFirst`, `FsGetFile`, `FsPutFile`, `FsExecuteFile`, ...) | Legacy C ABI surface; `ConnectionGuard` RAII |
| `DllExceptionBarrier.cpp` | C++ exception firewall at ABI boundary; DbgHelp stack trace | Every `Fs*` wrapped via `dll_invoke` |
| `ConnectionNetwork.cpp` | Socket creation, IPv4/IPv6 resolution, raw connect | Isolated network stage |
| `ProxyNegotiator.cpp` | HTTP CONNECT, SOCKS4/4a/5 negotiation | Dedicated proxy module |
| `JumpHostConnection.cpp` | Bastion host auth + `direct-tcpip` tunnel | No external `ssh.exe` |
| `SshSessionInit.cpp` | SSH session bootstrap (handshake, banner) | Modular session init |
| `ConnectionAuth.cpp` | Auth method dispatch | Triggers fallback chain |
| `SessionPostAuth.cpp` | Post-auth session steps (shell, SFTP init) | Separated from auth |
| `ConnectionDialog.cpp` | Connection dialog and UI handlers | `UpdateCertSectionState` consolidates cert section enable/disable for all transport modes |
| `SftpAuth.cpp` | Auth helpers, key-mode selection | Native PPK-aware |
| `SftpConnection.cpp` | High-level connection orchestration | Split from legacy monolith |
| `SftpTransfer.cpp` | Native SFTP transfer path, resume | Streaming buffers; ATTR_SIZE fix |
| `ScpTransfer.cpp` | Native SCP transfer path | Dedicated SCP engine |
| `ShellFallbackTransfer.cpp` | `cat`/`dd`/base64 chunk pipeline | Compatibility-first fallback |
| `SftpRemoteOps.cpp` | Listing, remote file operations | Marker-aware parsing; `SftpSetAttr` |
| `SftpShell.cpp` | Shell channel execution, EAGAIN guards | |
| `TransferUtils.cpp` | Progress, rate, shared transfer helpers | |
| `PhpAgentClient.cpp` | PHP Agent HTTP operations (WinHTTP); TAR batch upload session (`TarUploadSession`, `PhpAgentUploadDirAsTar`); TAR batch download session (`TarDownloadSession`, `PhpAgentDownloadFilesAsTar`, `TAR_PACK`) | |
| `PhpShellConsole.cpp` | PHP Shell pseudo-terminal; keyboard input, Tab completion, Up/Down history navigation | |
| `ShellHistory.cpp` | Persistent command history — ring buffer (128 entries), atomic NTFS write, `%APPDATA%\GHISLER\shell_history.txt` | `ShellHistory.h` |
| `PpkConverter.cpp` | PPK v2/v3 → PEM conversion | BCrypt + Argon2; no tools |
| `PasswordCrypto.cpp` | DPAPI encrypt/decrypt, legacy XOR read | `DataBlob` RAII |
| `ImportSourceRegistry.cpp` | Registry of the `IExternalSessionSource` adapters | One entry per source program |
| `SecureCrtAdapter.cpp`, `PuttyAdapter.cpp`, `WinScpAdapter.cpp`, `FileZillaAdapter.cpp`, `KittyAdapter.cpp` | Per-source session enumeration and settings mapping | Registry / INI / XML / per-session files |
| `ImportCache.cpp` | Persisted enumeration results per source and channel | Survives restarts; per-channel prune |
| `ImportIoUtil.cpp` | Shared adapter primitives — percent codec, registry readers, env expansion, key-file routing | |
| `VirtualSessionRegistry.cpp` | Alias map for connected virtual sessions | TC-safe alias names |
| `ServerRegistry.cpp` | In-memory server profile registry | |
| `ProfileSettings.cpp` | INI read/write for connection profiles | |
| `LanPair.cpp` | PAIR1 auth protocol, UDP discovery, PBKDF2 | `namespace smb` |
| `LanPairSession.cpp` | LAN2 command protocol, file transfer session | `noexcept` public API; session timeout enforcement |
| `Libssh2Backend.cpp` | `ISshBackend` implementation over libssh2 | |
| `AuthMethodParser.cpp` | Parses server-advertised auth method list | |
| `FtpDirectoryParser.cpp` | `ls -la` output parser | Unicode-aware |
| `CoreUtils.cpp` | Base64, time conversion, string utilities | Self-contained |
| `UnicodeHelpers.cpp` / `UtfConversion.cpp` | UTF-8 ↔ wide string conversion | |
| `WindowsUserFeedback.cpp` | `IUserFeedback` implementation | Decouples UI from logic |
| `PluginHelp.cpp` | Opens `sftpplug.chm` from plugin directory | |

---

## Source Tree

```
build.ps1                      # PowerShell build script (multi-language or single-language; x64 + x86)
bin/
  SFTPplug.zip                 # Release archive (TC auto-install) — only file produced here
build/
  SFTPplug.vcxproj             # MSVC project (C++20 / C17, x64 Release + x86 Release)
  SFTPplug.sln
  SFTPplug.vsprops
src/
  agent/
    sftp.php                   # PHP Agent (maintained source)
    sftp_php74.php             # PHP 7.4 compatibility variant
  core/
    *.cpp                      # All plugin modules (see Module Map)
    ShellHistory.cpp           # Persistent command history manager
  help/
    index.html
    authentication.html
    jump-host.html
    lan-pair.html
    php-agent.html
    php-agent-operations.html
    php-shell.html
    proxy-configuration.html
    sessions.html
    shell-commands.html
    shell-fallback.html
    transfer-modes.html
    security.html
    troubleshooting.html
    troubleshooting-advanced.html
    settings-reference.html
    encoding.html
    quickstart.html
    import-migration.html
    sftpplug.hhp               # HTML Help Workshop project
    sftpplug.hhc               # Table of contents
    sftpplug.hhk               # Index
    readme.txt                 # readme.txt distributed inside SFTPplug.zip
  include/
    global.h                   # Master header, debug config, C++20 guards
    ISshBackend.h              # Pure-virtual SSH backend interface
    SftpInternal.h             # Connection state structs
    DllExceptionBarrier.h      # ABI exception firewall
    ShellHistory.h             # Persistent command history interface
    CoreUtils.h
    LanPair.h                  # smb:: namespace, PAIR1/LAN2 types
    LanPairSession.h
    *.h
    libssh2/
      libssh2.h
      libssh2_sftp.h
      libssh2_publickey.h
  lib/
    argon2_a_x64.lib           # Argon2 static lib — x64, /MT (rebuilt from source)
    argon2_a_x86.lib           # Argon2 static lib — x86, /MT (rebuilt from source)
    libssh2_x64.lib            # libssh2 static lib — x64, WinCNG, /MT (rebuilt from source)
    libssh2_x86.lib            # libssh2 static lib — x86, WinCNG, /MT (rebuilt from source)
  res/
    sftpplug.rc                # String tables: EN / PL / DE / FR / ES
    resource.h
    icon*.ico
third_party/
  build.ps1                    # Builds all dependency libs (argon2 + libssh2, x64 + x86, /MT)
  argon/
    vs2026/
      Argon2Static/
        Argon2Static.vcxproj   # MSVC project: argon2_a_x64.lib / argon2_a_x86.lib, /MT
    build/
      x64/argon2_a_x64.lib    # (build artifact — excluded from git)
      x86/argon2_a_x86.lib    # (build artifact — excluded from git)
  libssh2/
    ...                        # libssh2 source (excluded from git via .gitignore)
    bld_x64/                   # (build artifact — excluded from git)
    bld_x86/                   # (build artifact — excluded from git)
```

---

## Build System

`build.ps1` (project root) compiles the plugin using MSBuild with the MSVC v145 toolset. Both x64 and x86 targets are built by default and packaged together in a single ZIP.

**Default (all languages in one binary, x64 + x86):**

```powershell
.\build.ps1
```

**Single-language builds (smaller binary):**

```powershell
.\build.ps1 -en   # English
.\build.ps1 -pl   # Polish
.\build.ps1 -de   # German
.\build.ps1 -fr   # French
.\build.ps1 -es   # Spanish
```

Single-language mode strips unused RC language blocks before compile and restores them afterward. Both x64 and x86 are still built.

**Output after a successful build:**
- `bin\SFTPplug.zip` — only file remaining in `bin\`; auto-deployed to TC plugin directory
- ZIP contains both `SFTPplug.wfx64` (x64) and `SFTPplug.wfx` (x86)
- ZIP file timestamp is set to `2030-01-01 00:00:00` (dependency-free release marker)
- Intermediate files (`build\bin\`, `build\.intermediates\`) are fully removed

**Release configuration:**
- Standard: `stdcpp20` (C++20), `stdc17` (C17)
- Optimization: `MaxSpeed`
- Runtime library: `MultiThreaded` (`/MT`, static CRT — no VC++ Redistributable required)
- Whole program optimization: enabled
- `NDEBUG` defined → `SFTP_DEBUG_ENABLED=0`, `SFTP_DEBUG_TO_FILE=0`

**Debug configuration:**
- `SFTP_DEBUG_ENABLED=1` → `OutputDebugString` output
- `SFTP_DEBUG_TO_FILE=0` by default; set to 1 manually for file logging to `C:\temp\sftpplug_debug.log`

**Rebuilding dependency libraries (`third_party/build.ps1`):**

All dependency static libs (argon2 and libssh2) can be rebuilt from source:

```powershell
.\third_party\build.ps1           # Build all (argon2 + libssh2, x64 + x86)
.\third_party\build.ps1 -argon    # argon2 only
.\third_party\build.ps1 -libssh2  # libssh2 only
.\third_party\build.ps1 -x64only  # x64 only
.\third_party\build.ps1 -x86only  # x86 only
```

Output libs are placed in `src\lib\` (suffixed: `argon2_a_x64.lib`, `argon2_a_x86.lib`, `libssh2_x64.lib`, `libssh2_x86.lib`). The script verifies `/MT` (`LIBCMT`) linkage in every output lib before copying.

---

## System Requirements

| Component | Requirement |
|-----------|-------------|
| Windows | Windows 7 or later (Windows 10/11 recommended) |
| Total Commander | Version 9.0 or later (x64 or x86) |
| Architecture | x64 (`SFTPplug.wfx64`) and x86 (`SFTPplug.wfx`) |
| Compiler (build) | Visual Studio 2026, MSVC v145 toolset, C++20 |
| libssh2 | Statically linked (1.11.1), built against OpenSSL |
| OpenSSL | Statically linked (3.5.7) — the crypto backend libssh2 runs on |
| **Dependencies** | None — OpenSSL, libssh2 and argon2 are statically linked with `/MT`, so no VC++ Redistributable is required |
| Windows APIs | BCrypt, DPAPI (CryptProtectData), WinHTTP, DbgHelp, Winsock2 |

---

## Packaging and Installation

Distribution archive: `SFTPplug.zip`

| File | Purpose |
|------|---------|
| `SFTPplug.wfx64` | x64 plugin binary (statically links libssh2 and Argon2, `/MT`) |
| `SFTPplug.wfx` | x86 plugin binary (statically links libssh2 and Argon2, `/MT`) |
| `pluginst.inf` | Total Commander auto-install descriptor (`file=` x86, `file64=` x64) |
| `sftp.php` | PHP Agent script for HTTP transfer and shell modes |
| `SFTPplug.chm` | Full offline documentation |
| `readme.txt` | Package notes |
| `language\pol.lng` | Polish |
| `language\rus.lng` | Russian |
| `language\deu.lng` | German |
| `language\fra.lng` | French |
| `language\esp.lng` | Spanish |
| `language\ita.lng` | Italian |
| `language\cs.lng` | Czech |
| `language\hu.lng` | Hungarian |
| `language\nl.lng` | Dutch |
| `language\pt-br.lng` | Brazilian Portuguese |
| `language\ro.lng` | Romanian |
| `language\sk.lng` | Slovak |
| `language\uk.lng` | Ukrainian |
| `language\ja.lng` | Japanese |
| `language\zh-cn.lng` | Simplified Chinese |

No external DLLs required. libssh2 and Argon2 are both rebuilt from source with `/MT` (static CRT) and statically linked into the binary — no VC++ Redistributable needed on the target system.

Open `SFTPplug.zip` in Total Commander and press Enter to trigger the plugin install prompt.

---

## Localization

On startup the plugin reads `HKCU\Software\Ghisler\Total Commander\IniFileName` to locate `wincmd.ini`, then reads `LanguageIni` from the `[Configuration]` section (e.g. `WCMD_POL.LNG` → Polish, `WCMD_CZ.LNG` → Czech, `WCMD_JP.LNG` → Japanese). The matched language ID selects the correct `.lng` file. Language loading is triggered from both `FsSetDefaultParams` and `FsInit` to cover all TC load orders.

The binary ships with an English-only compiled resource (`sftpplug.rc`). All non-English translations are provided as external UTF-8 files in the `language\` subdirectory and loaded at runtime via `LngLoader`. Dialog labels, checkboxes, buttons and window captions are all translated dynamically in `WM_INITDIALOG` using `SetDlgItemTextW`. Layout of variable-length rows (e.g. the Jump host line) is adjusted dynamically based on measured text width so all languages fit without overlap or excessive gaps.

| File | Language |
|------|----------|
| *(binary)* | English (US) — built-in fallback |
| `language\pol.lng` | Polish |
| `language\rus.lng` | Russian |
| `language\deu.lng` | German |
| `language\fra.lng` | French |
| `language\esp.lng` | Spanish |
| `language\ita.lng` | Italian |
| `language\cs.lng` | Czech |
| `language\hu.lng` | Hungarian |
| `language\nl.lng` | Dutch |
| `language\pt-br.lng` | Brazilian Portuguese |
| `language\ro.lng` | Romanian |
| `language\sk.lng` | Slovak |
| `language\uk.lng` | Ukrainian |
| `language\ja.lng` | Japanese |
| `language\zh-cn.lng` | Simplified Chinese |

### Language override

If TC uses a language the plugin cannot auto-detect (custom/community language file, or a language not in the supported 15), the UI falls back to English. This can be overridden via `[Configuration]` in `sftpplug.ini`:

```ini
[Configuration]
Language=English
```

Accepted values: `English`, `Polish`/`pol`/`pl`, `German`/`deu`/`de`, `French`/`fra`/`fr`, `Spanish`/`esp`/`es`, `Italian`/`ita`/`it`, `Russian`/`rus`/`ru`, `Czech`/`cs`, `Hungarian`/`hu`, `Japanese`/`ja`, `Dutch`/`nl`, `Portuguese`/`pt-br`, `Romanian`/`ro`, `Slovak`/`sk`, `Ukrainian`/`uk`, `Chinese`/`zh-cn`.

Custom `.lng` files are also supported: place `language\fin.lng` in the plugin directory and set `Language=fin`. Any string not found in the file falls back to English automatically.

The file `sftpplug.tpl` (shipped with the plugin) is copied to `sftpplug.ini` on first run as a template with documentation comments.

To add a new language: create `language\XYZ.lng` (UTF-8) following the existing format (`ID=text`, `#` comments, RC-style `\n \t \\` escapes) and deploy it alongside the plugin. If you want full LANGID mapping (Windows locale for date/number formatting), also add the code to `LangIdToTcCode` in `LngLoader.cpp`.

---

## Roadmap

### Completed

- ISshBackend abstraction layer
- Native PPK v2/v3 conversion (BCrypt + Argon2, no tools)
- Shell DD/base64 fallback transfer
- LAN Pair transport (PAIR1 auth, LAN2 protocol, UDP discovery, DPAPI trust, TOFU)
- LAN Pair session timeout (configurable, enforced at session level)
- Session import from PuTTY and WinSCP registry
- Remote checksum (MD5/SHA1/SHA256/SHA512)
- SCP >2 GB detection
- DPAPI + TC Master Password integration
- SFTP resume fix (`LIBSSH2_SFTP_ATTR_SIZE`)
- `FsSetAttrW` implementation (lstat → RMW → setstat)
- Setstat null guard (SCP mode)
- Tilde symlink protection
- December month parse fix (`FtpDirectoryParser`)
- Debug logging disabled in Release
- `DllExceptionBarrier` — ABI exception firewall with DbgHelp stack trace
- `ConnectionGuard` RAII — leak-free connection lifecycle in `FsFindFirstW`
- `UpdateCertSectionState` — unified cert section control for all transport modes
- x64 and x86 packaging — single ZIP with both architectures, TC auto-install via `pluginst.inf`
- PHP Shell persistent command history — ring buffer (128 entries), atomic NTFS write, `%APPDATA%\GHISLER\shell_history.txt`, `history -c` / `clear history` commands
- **`[Imports]` magic folder** — sessions from SecureCRT, PuTTY, WinSCP, FileZilla and KiTTY listed as live entries, one subfolder per source; `Enter` connects, `F5` materialises into `sftpplug.ini`; per-source `[Refresh]` and custom portable locations; enumeration cached next to the INI so entries are present at startup
- **KiTTY password import** — obfuscated session passwords decoded natively (`KittyDecrypt.cpp`, no external helper binary) and re-stored as DPAPI
- **FileZilla password import** — base64-stored site passwords carried over; master-password sites left to the interactive prompt
- **15-language localization** — added CS/HU/NL/PT-BR/RO/SK/UK/JA/ZH-CN; all auto-detected from TC `wincmd.ini` `LanguageIni` setting
- **Language override** — `Language=` key in `[Configuration]` of `sftpplug.ini`; supports all 15 built-in languages by name/ISO code, plus custom `.lng` stems for unsupported languages; `sftpplug.tpl` template shipped with the plugin
- **LAN Pair strict roles** — Donor/Receiver/Auto with unidirectional enforcement; Donor starts file server and refuses outgoing connections; Receiver connects as client without starting a local server
- **LAN Pair TrustedInstaller** — per-connection TI impersonation on the Donor server; per-transfer TI impersonation on the Receiver client; `CRYPTPROTECT_LOCAL_MACHINE` for DPAPI trust keys; auto-delete stale keys + auto-retry on first connect failure
- **Session delete fix** — single-character session names (e.g. `1`, `2`) can now be deleted via F8/Del
- **KiTTY password decoding** — the obfuscation KiTTY applies to stored session passwords is reversed in-process (`KittyDecrypt.cpp`); no external binary, no CAB resource, no antivirus exclusions involved. Decoded value is immediately re-protected with DPAPI
- **PHP Agent TAR upload** — opt-in `php_tar` checkbox; directory F5 copy streams a single POSIX ustar TAR POST to `op=TAR_EXTRACT`; PHP extracts on-the-fly; GNU LongLink for long paths; two-pass Content-Length; works in foreground (`PUT_MULTI`) and background thread (`PUT_MULTI_THREAD`) modes; plain `.tar` file uploads unaffected
- **PHP Agent TAR batch download** — opt-in `php_tar` checkbox; multi-file F5 copy sends a single POST to `op=TAR_PACK` with all remote paths; server streams ustar TAR directly without buffering (`php://output`); plugin parses TAR on-the-fly and writes local files; works in foreground (`GET_MULTI`) and background thread (`GET_MULTI_THREAD`) modes; GNU LongLink supported; files >8 GiB skipped cleanly
- **PHP Agent TAR fixes** — DWORD overflow (TAR upload >4 GB now uses 64-bit `Content-Length` header); TAR pack no longer buffers in `php://temp` on server (eliminates HTTP 504 on OVH); per-file zero-pad allocation removed from upload loop; >8.5 GiB file guard in both C++ and PHP prevents TAR header corruption

### Fork additions (10.x)

User-facing summary; see `CHANGELOG.md` for per-version detail.

- **Broader SSH algorithm support** — libssh2 switched to OpenSSL crypto backend so modern host keys, key exchanges and ciphers (required by default by many up-to-date OpenSSH servers) are accepted where they used to fail with "no matching algorithm"
- **Public-key auth with private-key-only configuration** — empty public-key field no longer prevents the key being tried; the public component is derived from the private one
- **Jump host (ProxyJump) stability** — multiple crashes and edge cases fixed (missing jump credentials, jump fingerprint validation, disconnect during jump negotiation)
- **Server-side file handle leak** fixed — each transfer no longer leaks a handle until the connection is closed
- **Multi-second freeze on disconnect** fixed — libssh2 cleanup wait is now bounded
- **Lower CPU during transfers** — `EAGAIN` busy-waits replaced with event-driven socket waits
- **Jump host by saved-session reference** — F7 connection dialog has a picker that lets you point a session at another saved session as its jump host; edit-once-propagates semantics (OpenSSH `ProxyJump`-style); missing/deleted targets show as `[!] name (missing)`
- **F3 / F4 on a saved session** shows its settings as an INI snippet, the same content F5 exports. Editing that snippet does not write back — Alt+Enter is the editable path
- **Diagnostic status lines are prefixed with the session name** — `[session] Upload file: …`, useful when multiple sessions are open in different TC tabs
- **Saved-session folders** — group sessions hierarchically via `/` in the DisplayName (`[home/raspi]`). F7 inside a folder creates a session there; F6 covers rename / move / cross-folder / bulk folder rename; F8 covers session and bulk folder delete; jump-host references stay valid across every rename. Padlock icon shown for folder-nested sessions. Backwards compatible with flat session profiles.
- **`[Active Sessions]` magic folder** — when at least one session is connected, a virtual folder appears in the plugin root. Entering it lists every active session in a flat view with a `[Disconnect All]` row at the top: F8 on a row disconnects that session; F8 on `[Disconnect All]` closes every connection at once; Enter on `[Disconnect All]` does the same and drops you back to the plugin root. The folder auto-hides when nothing is connected. No setup required.
- **Session import lives in the `[Imports]` folder** — the connection
  dialog's `Import...` button and the checkbox picker behind it are
  gone. Sessions from SecureCRT, PuTTY, WinSCP, FileZilla and KiTTY
  appear as live entries in the plugin root: `Enter` connects using the
  source program's settings, `F5` copies one into your own list, and
  `Ctrl+A` then `F5` takes a whole source at once.
- **The `Session:` field names the session** — it used to be a dropdown
  of every saved session, and picking one there loaded it into the
  dialog. Sessions are chosen in the panel; typing a different name in
  the field renames the session, and a name already in use is refused
  rather than overwritten.
- **Transparency** — argon2 (used internally for PuTTY PPK v3 key files) is now built from public source instead of a pre-compiled blob

### In Progress

- Splitting remaining oversized legacy functions
- C-style buffer replacement with `std::vector` / `std::string`
- Further UI/business-logic decoupling under WFX constraints
- Expanding CHM coverage for all modes and edge cases

### Planned / Deferred

- mDNS/SSDP cross-subnet discovery for LAN Pair
- UPnP automatic port forwarding
- Higher-level LAN Pair workflow refinements
- Alternative SSH backend (libssh)
- Multi-platform support (Linux / macOS)
- Full parser module rewrite

---

**Highlights:** DllExceptionBarrier (ABI protection), ConnectionGuard RAII, LAN Pair TOFU/timeout, PHP Shell persistent history, 15-language localization (CS/HU/NL/PT-BR/RO/SK/UK/JA/ZH-CN added), **`[Imports]` magic folder** covering SecureCRT / PuTTY / WinSCP / FileZilla / KiTTY with native KiTTY and FileZilla password decoding, **PHP Agent TAR upload+download** (streaming ustar POST/GET, on-the-fly server extraction, batch download via TAR_PACK, no 4 GB limit), no VC++ Redistributable required

*SFTP Plugin v10.0.2.x — Modern C++20 implementation.*
*Based on the original SFTP plugin by Christian Ghisler, and on the C++
rewrite by Marek Wesolowski ([kvc.pl](https://kvc.pl)) that this fork
continues.*
*Issues and pull requests for this fork:
[github.com/zvldz/totalcmd_sftp](https://github.com/zvldz/totalcmd_sftp)*
