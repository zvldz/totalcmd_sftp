# Changelog

User-facing summary of changes in this fork. Each version corresponds to a
build of `SFTPplug.zip`. Internal refactors, build-script tweaks, and other
developer-only changes are kept brief or omitted; the git log has the full
detail.

This fork started from wesmar's stock release 1.0.0.17 and bumped to the
`10.x` line to make divergence visible in TC's plugin manager.

## 10.0.1.5 — unreleased

### Features

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
