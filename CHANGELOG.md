# Changelog

User-facing summary of changes in this fork. Each version corresponds to a
build of `SFTPplug.zip`. Internal refactors, build-script tweaks, and other
developer-only changes are kept brief or omitted; the git log has the full
detail.

This fork started from wesmar's stock release 1.0.0.17 and bumped to the
`10.x` line to make divergence visible in TC's plugin manager.

## 10.0.1.5 — unreleased

### Features

- **Virtual sessions now show TC's connect-progress bar on Enter.**
  Before this pass, entering a session inside `[Imports]\...` did the
  SSH handshake silently inside our `FsExecuteFileW` handler — the
  panel just sat there for the couple of seconds it took to connect,
  with no visual indication that anything was happening. Now the
  handshake runs inside `FsFindFirstW`, the same call TC uses for
  real sessions, and TC decorates it with its native connect-progress
  dialog identical to what a real session shows on Enter. Two side
  benefits: connect failures now surface with TC's standard error
  message instead of failing silently, and entering a virtual session
  via a bookmark or a hand-typed path (previously broken) works
  correctly.

### Prior features (already shipped in earlier 10.0.1.5 beta tags)

- **`[Active Sessions]` magic folder.** A virtual folder appears in the
  plugin root whenever at least one saved session is connected.
  Entering it shows a flat list of every currently-open session by
  DisplayName (folder-nested sessions keep their slashes), with a
  `[Disconnect All]` row at the top. Press F8 on a row to disconnect
  that single session; F8 on `[Disconnect All]` closes everything at
  once. Pressing Enter on `[Disconnect All]` does the same and
  additionally drops you back to the plugin root in one gesture. The
  folder auto-hides when nothing is connected — no setup, no menu
  configuration. Useful when several sessions are open across TC tabs
  and you want to pick which one to close without tab-juggling.

- **`[Imports]` magic folder — SecureCRT sessions as live virtual entries.**
  A new `[Imports]` folder appears in the plugin root and lists every
  supported source program (SecureCRT is the first; PuTTY, WinSCP,
  KiTTY, FileZilla to follow). Inside a source folder:
  - `[Refresh]` re-scans and persists the session list to a cache next
    to `sftpplug.ini` — sessions survive TC restarts, appear
    immediately on the next launch.
  - `[Add custom location...]` lets you point the plugin at any
    portable install / backup folder in addition to the auto-detected
    location.
  - `[Manage custom locations]` lists what you've added; F8 removes an
    entry and prunes only its cached sessions.
  - Enter on a session connects using the cached settings.
  - F5 / drag onto another panel materialises the session into your
    own `sftpplug.ini` as a normal saved entry — from then on it
    behaves like any other session you created yourself. F5 / drag to
    a real filesystem path writes a portable INI snippet instead.
  - Cached sessions that become unreachable (source uninstalled, USB
    unplugged) stay visible until you explicitly remove them; refresh
    never prunes on failure to reach, only on an empty-but-reachable
    result.
  - Dropping a session-INI file onto the plugin root creates a new
    saved session in one gesture (reverse of the F5 export).

  SecureCRT specifics: reads `%APPDATA%\VanDyke\Config\Sessions\` and
  any custom path; passwords are intentionally not carried across —
  the standard interactive prompt kicks in on first connect, or you
  can save one via the Configure dialog. Non-SSH2 sessions are
  skipped.

- **`[Imports]\[PuTTY]` — PuTTY sessions as live virtual entries.**
  Same magic-folder UX as SecureCRT. Reads `HKCU\Software\SimonTatham\
  PuTTY\Sessions` (the standard registry key every PuTTY-compatible
  tool writes into — PuTTY itself, ExtraPuTTY, PuTTY CAC, and the
  tabbed runners mtPuTTY / SuperPuTTY that delegate storage back to
  PuTTY). `[Add custom location…]` accepts a portable
  `putty.reg` export file (the same one PortableApps'
  `PuTTYPortable\Data\settings\putty.reg` stores) — pick the file
  and its sessions merge into the source folder alongside the
  registry ones. Field mapping: `HostName` → `server`,
  `PortNumber` → server suffix, `UserName` → `user`,
  `PublicKeyFile` (`.ppk` / `.pem` / `.pub`) → key file, `AgentFwd`
  / `AuthAgent` → `useagent`, `LineCodePage` (`UTF-8`, `KOI8-R`,
  `KOI8-U`, `ISO-8859-N`, `CP1251`, `WIN-1252`, `Windows-1250`, and
  raw numeric codepages) → `utf8` / `codepage`, `EnterSendsCrLf` →
  `unixlinebreaks`. Proxy fields are intentionally not carried
  across for now — they need a separate cross-adapter materialise
  pass planned around Phase 4/5; PuTTY sessions behind a SOCKS/HTTP
  proxy import cleanly today but the proxy has to be re-entered
  manually on the materialised copy.

- **`[Imports]\[WinSCP]` — WinSCP sessions as live virtual entries.**
  Same magic-folder UX as PuTTY. Reads
  `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions` (standard
  install) and any portable `WinSCP.ini` you point
  `[Add custom location…]` at. FSProtocol is honoured correctly:
  SFTP-only (2) and SFTP-with-SCP-fallback (1) open as regular
  SFTP sessions, SCP-only (0) sessions force the plugin's SCP
  transport (`scponly=1`, `scpfordata=1`, `unixlinebreaks=1`,
  `largefilesupport=0` — matches WinSCP's own SCP-mode default),
  and unsupported transports (FTP / WebDAV / S3) are silently
  hidden from the folder. Field mapping is otherwise identical to
  PuTTY. Passwords are intentionally not imported.

- **`[Imports]\[FileZilla]` — FileZilla sessions as live virtual
  entries.** Same magic-folder UX. Reads
  `%APPDATA%\FileZilla\sitemanager.xml` (standard install) and any
  portable `sitemanager.xml` you point `[Add custom location…]` at.
  Only `Protocol=1` (SFTP) is exposed; FTP / FTPS / WebDAV / S3
  entries are silently hidden. Nested `<Folder>` elements become
  nested subfolders in the panel (`Team/prod/host1`). Key files
  are picked up from `<Keyfile>` — including OpenSSH-style paths
  without an extension (`id_rsa`, `id_ed25519`), which FileZilla
  routinely writes because its fzsftp back-end reads OpenSSH PEM
  directly. Passwords are intentionally not imported. Host-key
  fingerprints from `hostkeys.xml` are not inherited either — TC
  shows its own TOFU prompt on first connect, same as for any
  other imported session.

- **PPK ed25519 keys now work end-to-end.** Previously any imported
  or user-configured session pointing at an ed25519 `.ppk` failed
  auth silently (`PpkConverter` reported `unsupported_algorithm`;
  `SftpAuth` aborted with "Public-key auth aborted due to local key
  file error"). The converter now parses ed25519 PPK v3 blobs and
  emits a proper OpenSSH key container (`-----BEGIN OPENSSH PRIVATE
  KEY-----` — the same file format `ssh-keygen -t ed25519` writes),
  which libssh2 with the mbedTLS backend consumes directly. Fix
  applies plugin-wide, not just to Import-related paths: hand-
  configured sessions with `privkeyfile=<...>.ppk` benefit too.
  RSA / ECDSA PPKs are unchanged. Encrypted-ed25519 PPKs are not
  covered — the maintainer's use case does not need them yet;
  extend if a report shows up. Same for the Ed448 curve (PuTTY
  0.75+ can write it), tracked in TODO.

### Fixes

- **Import dialog (KiTTY Portable): `Default Settings` phantom row
  removed.** KiTTY's per-session file `Default%20Settings` stores
  defaults, not a real session, but with `Protocol=ssh` it passed the
  filter and showed up in the picker. Filtered out alongside the
  existing PuTTY/WinSCP handling.
- **Import dialog: session list now shows a column header.** The
  `SysListView32` column was inserted without `LVCF_TEXT`, so the
  header bar was visible but empty. Now reads `Session` (localisable
  via `IDS_IMP_LIST_HEADER`).
- **Shift+F5 (same-panel copy) on a session or folder no longer
  throws you out of the plugin.** After a successful copy the
  plugin was posting `cm_RereadSource` unconditionally; for
  same-panel intra-plugin copy this races with Total Commander's
  own post-copy refresh and threw the user to the other panel's
  drive root. The extra refresh is now sent only for rename
  (`F6` / Move=TRUE), where our INI changes are invisible to TC
  and an explicit refresh is genuinely needed.

### Internal

- Removed `src/core/ConnectionDialogClass.cpp` (an unfinished class-extraction
  refactor inherited from upstream) and the duplicate `src/php/sftp.php` (the
  canonical PHP agent script lives at `src/agent/sftp.php`). Pure dead-code
  cleanup, no behaviour change.
- Removed the dead `2030-01-01` ZIP timestamp marker from `build.ps1`. It was
  inherited broken (the LastWriteTime write ran before the FileStream was
  released, so nothing was ever set), the purpose was never documented, and
  mtime does not survive `git checkout` anyway. Simpler build script.

## 10.0.1.4 — 2026-06-24

### Features

- **Saved sessions can be grouped into folders.** When you accumulate enough
  saved sessions that a flat list becomes unwieldy, you can put them into
  folders that show up alongside regular sessions in the plugin root:
  - **F7 inside a folder** creates the session in that folder automatically.
  - **F6 (rename)** is the universal "move" gesture — type a destination
    path that includes a folder (e.g. `\work\web1`) and the session moves
    there. F6 on a folder bulk-renames every session in it.
  - **F8** on a folder removes the folder and every session inside (TC
    asks for confirmation as usual).
  - **Drag-and-drop** between panels works for both sessions and folders.
  - Folders are *implicit*: a folder exists while at least one session
    lives under it. No "create empty folder" step, no orphan placeholders.
  - **Jump-host references survive rename and move.** If session B uses A
    as its jump host and you rename A (or move A into a folder), B's
    reference is updated automatically — the by-reference jump picker
    won't surface a "missing" marker.
  - Backwards compatible: existing flat session profiles keep working
    unchanged.

- **F3 / F4 on a saved session opens the Edit Session dialog.** Same dialog
  you've always been able to reach via Alt+Enter or RMB → Properties; F3/F4
  now bind to it from the keyboard. Works for sessions both at the plugin
  root and inside folders.

### Fixes & UX polish

- **Editing a session in a folder** (Alt+Enter / Properties / F3 / F4) now
  opens the dialog like for a root-level session. Previously the action
  fell back to TC's "download as file" path and produced an "Error
  downloading file" popup.
- **The padlock icon** for saved sessions is now shown for sessions inside
  folders too, not just at the plugin root.
- **Connecting to a session in a folder** works the same as connecting to
  one at the root — Enter resolves the session and lands you in its
  remote filesystem.
- **Copy / move / paste of folders** through TC no longer pops a spurious
  empty "New Connection" dialog mid-transfer. (The dialog used to appear
  because TC probes the destination path before creating it; the plugin
  now recognises this pattern.)
- The "WebDAV" leftover in dialog resource names was renamed to "Connection"
  for clarity — the plugin has not implemented WebDAV in years.

## 10.0.1.3 — 2026-05-17

### Features

- **Jump host by saved-session reference.** In the F7 connection dialog
  there is now a dropdown next to the Jump button that lets you pick an
  existing saved session as the jump host. Selecting a session links its
  network/auth settings by reference, so editing the jump session once
  propagates to every session that uses it as a jump (the OpenSSH
  `ProxyJump` model). Missing/deleted target sessions show up as
  `[!] name (missing)` markers in the picker.
- **Diagnostic status messages are prefixed with the session name**
  (`[session] Upload file: ...`). Useful when you have several connections
  open in different TC tabs and want to see which one is reporting status.

### Fixes & polish

- F3 / F4 on a saved session entry now opens the Edit Session dialog
  (alternative to Alt+Enter). 10.0.1.4 extended this to sessions inside
  folders; in 10.0.1.3 it works for root-level sessions only.
- `Get directory:` status lines use forward slashes to match the rest of
  the SFTP/SCP status output (was a stray backslash before).
- The plugin help text reachable from `[F7 = new connection]` mentions
  the F3/F4 shortcut.
- `build.ps1` no longer fails with a misleading "could not remove bin"
  warning when an indexer or AV holds the output directory open; it now
  only removes the zip artifact.

### Transparency

- The argon2 library (used internally for PuTTY PPK v3 key files) is now
  built from its public source instead of being shipped as a pre-compiled
  binary that came with the upstream codebase. Anyone reviewing the
  plugin can now see exactly what third-party code goes into the build.

## 10.0.1.2 — 2026-05-11

### Fixes

- **Server-side file handle leak.** Each transfer used to leave a handle
  on the server until the connection was closed; long-running sessions
  could eventually exhaust the server's per-connection handle limit.
  Handles now close deterministically after every transfer.
- **Disconnect no longer freezes Total Commander for several seconds.**
  When tearing down a session, the plugin used to spin on the libssh2
  cleanup path even when the network was already gone. Cleanup now
  bounds the wait.
- **CPU usage during transfers** is significantly lower. The wait loops
  around `EAGAIN` on libssh2 calls used to be busy spins; they now wait
  on the underlying socket and wake when data is actually ready.

## 10.0.1.1 — 2026-05-07

### Fixes

- **Public-key authentication** with only a private key configured (no
  public key field set) now works. Previously the plugin refused to try
  the key — the public component is computed from the private one
  internally.
- **Jump host (ProxyJump) stability.** Several scenarios that used to
  crash or hang the plugin are fixed: missing jump credentials, jump
  fingerprint validation edge cases, and disconnect during jump
  negotiation.

## 10.0.1.0 — 2026-05-07

### Features

- **Broader SSH algorithm support.** The plugin's SSH layer now runs on
  the OpenSSL crypto engine instead of the previous Windows-built-in
  backend. The user-visible effect is that modern host keys, key
  exchanges and ciphers — the ones many up-to-date OpenSSH servers
  require by default — are now supported, so connections that used to
  fail with "no matching algorithm" against newer servers go through.
