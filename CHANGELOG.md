# Changelog

User-facing summary of changes in this fork. Each version corresponds to a
build of `SFTPplug.zip`. Internal refactors, build-script tweaks, and other
developer-only changes are kept brief or omitted; the git log has the full
detail.

This fork started from wesmar's plugin as of 24 March 2026.

## 10.4.0.0 — unreleased

Fixes and improvements taken over from
[wesmar/sftp 10.3.0.0](https://github.com/wesmar/sftp), which is based on
this fork's 10.0.2.2. Each entry names where it came from.

From this version the plugin comes in two builds: **classic**
(`SFTPplug-<version>.zip`, SSH only) and **extra**
(`SFTPplug-<version>-extra.zip`, + PHP Agent, PHP Shell, LAN Pair).

### Security

- **A session file from elsewhere no longer pre-trusts a host key.**
  Dropping a session file onto the plugin took over its stored host and
  jump-host fingerprints, so a crafted file could make the first
  connection accept a key without asking. Those keys are now left out and
  the first connection asks as for any new host.
- **"Use SSH agent" no longer loses the saved password.** With the agent
  ticked, a password or passphrase kept in the plugin's settings (not in
  Total Commander's password manager) was not loaded: the key file tried
  after Pageant missed its passphrase, the password was asked for, and
  OK in the session's dialog wrote the empty field back, deleting it.
  Imported PuTTY, KiTTY and WinSCP sessions have the agent ticked by
  default. The key-file fields also stay editable with the agent on.
- **A mistyped password is not sent again.** A password typed at a
  keyboard-interactive prompt became the session's password at once and
  was sent again, unasked, at the next prompt and by the password method:
  one typo cost two or three failed logins (fail2ban, account lockout).
  It is kept only once the login succeeds; a refused one is asked anew.
  The same for a jump host's password typed at its prompt.
- **A jump session that needs a jump host itself is refused.** A session
  with "use jump host" ticked but none named (its reference was deleted)
  is refused when opened on its own, yet was used as a plain jump host by
  sessions referring to it, skipping the bastion it asks for.
- **Debug log and crash hooks.**
  - The log of a test build is written to `%TEMP%\sftpplug.log`, which
    only the user can open, instead of `C:\temp`, where other users of the
    machine could read it or put a file in its place. Quote commands, the
    SFTP server command and SCP commands are no longer written to it.
  - The crash hooks are installed only in a build with the log on, since
    the log is all they write to. The vectored handler logs only
    exceptions raised in the plugin; before, it built a stack trace for
    every exception in Total Commander and its other plugins.
  - The plugin no longer replaces the C runtime's invalid-parameter
    handler, whose default stops at once: with the replacement, an
    overflow caught by a checked string function carried on.
  - A crash filter set after the plugin's is not removed when the plugin
    is unloaded.
  - A release built from a stable tag is refused when the log is on or the
    tag does not match the version in the sources.
- **System DLLs from System32 only.** `dbghelp.dll` and `version.dll` are
  loaded when first needed and only from System32, so a file of that name
  beside Total Commander is not loaded instead.
- **A session file can no longer take a password from the password
  manager.** A file dropped onto the plugin with `password=!` and a server
  of its choosing was given the password Total Commander's password
  manager kept under the same session name, and the plugin sent it to
  that server. A `!` in a file now brings no password. Passwords a file
  does carry, for the session, its jump host or its proxy, go into the
  password manager under the master password; when there is none yet,
  Total Commander offers to create one. A password the manager does not
  take is not kept and is asked for on connect.
- **The jump host's password can be kept under the master password.** The
  "Protect password with password manager" box in the jump-host settings
  did nothing: the password always went into `sftpplug.ini`. It is now
  kept in the password manager when ticked, and a jump host taken from
  another session whose password is kept there gets that password at
  connect — before, it got a placeholder byte instead.
- **"Protect password with password manager" is ticked for new
  passwords** — session, proxy and jump host. Copying a session from
  [Imports] into the own list puts its password into the password
  manager even when no master password is set yet: Total Commander offers
  to create one, where before the password was silently dropped.
- **Passwords follow the session in the password manager.** Renaming a
  session in its settings left the password behind under the old name
  ("Failed to load password!"), and jump hosts pointing at the session
  lost it; it now works like F6. Deleting a proxy, or unticking the
  password manager box, leaves no entry in the password manager for a
  later record or session with the same name to pick up. The proxy
  dialog ticks the box by where its own password is kept, not by the
  session's.
- **Session files copied out carry the passwords readable.** F3/F5 on a
  session or a proxy record writes its passwords as
  `plain:<password>`, loading one kept under the master password (Total
  Commander asks for it). Before, the file carried the stored form,
  which no other machine can read, or none at all. An [Imports] session
  copied out carries the source program's password.
- **A key passphrase is no longer sent to the server as the password.** A
  password field holding the key's passphrase (the plain form, not
  `"password","passphrase"`) was offered to the server as the account
  password once the server turned the key down. When it is seen to open
  the key, the password is asked for instead; the same for a jump host.
- **One-time codes get no stored password.** A keyboard-interactive
  prompt for a PASSCODE (RSA SecurID, Duo), token or verification code
  took the stored password, and a code typed there was kept and replayed
  as the password on reconnect. A jump host answers with its password
  only once per login.
- **Passwords are wiped from memory with the connection**, and a password
  the server makes you change during a background transfer is saved the
  way the session keeps its own — before, it went into `sftpplug.ini`
  even for a session whose password is under the master password.
- **A proxy is no longer skipped when a jump host is set too.** The jump
  host was reached straight from this machine and the session's proxy
  ignored without a word, as was the proxy of a session used as the jump
  host. Such a session is now refused with a message, and the connection
  dialog does not save a proxy together with a jump host.
- **A session file whose proxy is missing is not imported.** One set to
  use a proxy the file does not describe was imported without it, to
  connect directly; it is now refused. A proxy record that cannot be
  written stops the import too, instead of leaving the session pointing
  at nothing.
- **Imported sessions keep their proxy and jump host on every connect.**
  - The check that refuses an [Imports] session going through a route the
    plugin does not reproduce ran on Enter only; a reconnect or background
    transfer after [Refresh] added such a route went direct. It now runs
    on every connect.
  - A session changed in its source program since the last scan is
    refused until [Refresh]: its new password was sent to the old host, or
    its new proxy or jump host skipped. The session is read again from the
    source on every connect, copy and background transfer, with or without
    a saved password.
  - OpenSSH: a ProxyJump or ProxyCommand in a `Match` block was ignored.
    `Match all` and `Match host` are now applied like `Host`; with other
    conditions, which the plugin cannot evaluate, the session is refused.
  - OpenSSH: an `Include` inside a `Host` block could switch that block off
    for the lines after it, so a `ProxyJump` written below the `Include`
    was dropped and the session imported as a direct connection. As in
    `ssh`, the block's state now comes back after the included file, and
    an `Include` inside a block that does not apply brings nothing in.
  - WinSCP: a proxy or tunnel set in "Default Settings", which WinSCP
    applies to every session that does not override it, was not seen. The
    same for the port, user name and protocol.
  - FileZilla: a `filezilla.xml` that exists but cannot be read was taken
    as "no proxy"; the session is now refused. KiTTY reads a session file
    once, so a file locked between two reads cannot hide its proxy.
- **A changed host key is reported on a reconnect too.** A connection
  restored mid-transfer had lost the means to ask, so a server presenting
  another key was refused without a word — no warning that someone might
  be in between. It now asks as the first connection does.
- **A proxy host name of 250 characters or more no longer overruns a
  buffer**; one too long for it is refused.
- **Cancelling a password change no longer crashes or loops.** A server
  that forces a new password, with the prompt cancelled, sent the plugin
  back into the SSH library with a state it had already freed.
- **Connecting gives up instead of spinning.**
  - A proxy that dropped the connection while the plugin was writing or
    reading kept it busy at full CPU until cancelled.
  - The SSH handshake and a jump host's login had no time limit; a
    server that stopped answering kept the connection waiting for good.
    The SFTP channel reopened mid-session waited without pause or limit,
    and so did the post-login command.
  - Cancel during the TCP connect went on to the server's next address
    instead of stopping.
- **A one-time code can be typed at leisure.** The 10-second limit of a
  login step counted the time spent at the prompt, so a code from a
  phone app often came too late.
- **Pageant and a key file together.** With "Use SSH agent" on, the key
  file of the session was never tried, although the help said it would
  be after Pageant.
- **Host names in any script.** Server and jump-host names with
  characters outside the Windows codepage are looked up correctly; the
  jump host follows the session's IPv4 / IPv6 choice.
- **A remote name with a backslash is no longer shown.** Total Commander
  takes `\` for a separator: "a\b" was handled as file b in folder a, F8
  on it could delete another file, and a server could list
  "..\..\x.bat" to have a download land outside the target folder. Such
  names are skipped, with a line in the log.
- **Downloads land where they belong.** A remote file named like a
  device (`nul`, `con.txt`, `com1`) was written to the device — the data
  went nowhere, the copy "succeeded", and a move then deleted the
  original. A name ending in a dot or space lost it and could replace
  another file; `<` and `>` were not allowed either. Such names are now
  saved with the offending character replaced by `_`.
- **A file name can no longer rewrite a shell command.**
  - SCP-only and shell-transfer sessions send commands to a shell on a
    terminal, whose line handling acts on control characters before the
    shell sees the quotes: a name holding ^U, ^C or DEL could replace the
    command with one of its own. A command with such a character is not
    sent; the operation fails.
  - In a session with a codepage other than UTF-8, a character the
    codepage lacks was replaced by a look-alike: a fullwidth apostrophe
    became a real quote inside the command, and two names could become
    one. Such a name is now refused instead of altered.
  - The markers that delimit a command's output are random, so a file
    named like one can no longer end a listing early.
- **PHP Agent and LAN Pair moved to a separate extra build.** They open
  the machine to the network in ways SSH does not: LAN Pair runs a file
  server on it, PHP Agent drives a script on a web server, with a shell.
  The classic build leaves their code out entirely — no LAN Pair server,
  no HTTP client, no TrustedInstaller code in the binary. Both builds use
  the same file names and the same `sftpplug.ini`, so one installs over
  the other. A PHP Agent or LAN Pair session met by the classic build is
  not connected (a message names the extra build, nothing is tried over
  SSH) and opens read-only in its settings, so its mode is never
  rewritten. The extra build says so in the connection dialog's title,
  the help page title and the file description; `sftp.php` and the PHP
  Agent / LAN Pair help pages ship only with it.
- **LAN Pair and PHP Agent follow wesmar's implementation.** Both are
  taken from [wesmar/sftp](https://github.com/wesmar/sftp) 10.3.1.0 as
  they are, in place of this plugin's own fixes for
  [wesmar/sftp#8](https://github.com/wesmar/sftp/issues/8) and
  [#9](https://github.com/wesmar/sftp/issues/9), so the two plugins work
  together: a computer with this one pairs with a computer running his,
  and both talk to the same `sftp.php`. Changes to these parts keep that
  compatibility. *From wesmar/sftp 10.3.1.0.*
- **LAN Pair is encrypted and needs the pairing password.** Any machine
  on the same network could ask LAN Pair's file server for a new trust key
  and get it, then read, write and delete files on every drive. Now the
  two computers prove to each other that they hold the same password
  without sending it (SPAKE2, RFC 9382), and everything after that travels
  in AES-256-GCM. A key is stored only once the peer has proved the same
  one; pairing without a password is no longer possible. The
  TrustedInstaller token is taken only after the handshake. Both
  computers need this version (or wesmar's 10.3.1 or later); an older one
  is told to upgrade. *From wesmar/sftp 10.3.1.0, wesmar/sftp#8.*
- **PHP Agent requests are signed, the password no longer travels.** It
  went with every request in a header, readable over plain HTTP. Now every
  request is signed with HMAC-SHA256 over its operation, parameters, body,
  time and a single-use nonce, and the agent checks a body before using
  it. Upload the new `sftp.php` (agent 1.1.0): an older agent is refused
  with a message saying so. As in wesmar's agent, shell commands stay on
  by default (`AGENT_ALLOW_SHELL = false` turns them off) and go in the
  URL. *From wesmar/sftp 10.3.1.0, wesmar/sftp#9.*
- **LAN Pair ports are open only while LAN Pair is used.** The file server
  and discovery started as soon as the plugin loaded, for everyone, even
  without a single LAN Pair session, and ran until Total Commander exited.
  Now they start when a LAN Pair session is opened or Pair... is clicked,
  and stop when the last LAN Pair session closes. A Donor has to open its
  session once before the Receiver connects, and then serves until Total
  Commander exits. The TCP ports are bound exclusively, so no other
  program can take them over; discovery's UDP port is still shared.
  *wesmar/sftp#8.*
- **LAN Pair keys readable only by your Windows account.** They were
  encrypted with machine-wide DPAPI, so any other account on the computer
  could decrypt them. Keys stored earlier, and keys stored by wesmar's
  plugin, keep working. *wesmar/sftp#9.*
- **A crafted FileZilla file can no longer crash Total Commander.** The
  importer read nested XML elements with no depth limit, so a file nested
  deep enough overflowed the stack. Files nested deeper than 64 levels are
  now skipped, with a line in the log. *wesmar/sftp#9.*
- **No silent fallback to weak password storage.** When Windows could not
  encrypt a password with DPAPI, the plugin saved it XOR-ed with a key
  published in its source. Now the password is not saved, the log says
  why, and it is asked for on the next connect. Passwords saved in the old
  format are still read. *wesmar/sftp#9.*
- **Imported passwords no longer kept by the plugin.** Opening a KiTTY or
  FileZilla source decrypted the password of every session in it and
  stored them all in `sftpplug-imports-cache.ini`; copying a session with
  F5 then put its password into `sftpplug.ini`, past Total Commander's
  master password. Now the password of one session is read from the source
  when that session is connected and kept in memory only. F5 puts it into
  Total Commander's password manager when a master password is set, and
  otherwise does not copy it: it is asked for on connect and can be saved
  under Alt+Enter. A new password the server makes an imported session
  set is not written back either. Passwords already in the cache file are
  removed from it. *wesmar/sftp#9.*
- **Stack buffer checks are on.** The plugin is built with `/GS`, so a
  stack buffer overrun ends the process instead of running whatever
  overwrote the return address. Control Flow Guard and CET were already on.
  *From wesmar/sftp 10.3.0.0.*
- **Control Flow Guard also in OpenSSL and libssh2.** The plugin's own code
  was built with it, the two libraries it links were not, so the guard
  stopped at their code. *From wesmar/sftp 10.3.0.0.*
- **OpenSSL reads no configuration file and carries only what SSH uses.**
  A stray `openssl.cnf` or `OPENSSL_CONF` on the machine could reconfigure
  the crypto inside Total Commander's process; the plugin now forbids it at
  start-up and OpenSSL is built without the default lookup. Algorithms SSH
  does not negotiate are left out of the build, and with them the obsolete
  `ssh-dss` keys, the `blowfish-cbc`, `cast128-cbc` and `arcfour` ciphers
  and `hmac-ripemd160`. *From wesmar/sftp 10.3.0.0.*

### Features

- **SFTP through a server command.** A session can name the SFTP server
  to run, for example `/usr/libexec/sftp-server`, and the plugin executes
  it instead of requesting the `sftp` subsystem — like `sftp -s` in
  OpenSSH. Hosts such as OpenWrt or Dropbear that have the binary but no
  subsystem then work in SFTP mode. Set under More... in the connection
  dialog (`sftpservercommand` in `sftpplug.ini`). The feature first
  appeared in numbereleven-a's fork; the libssh2 patch is
  *from wesmar/sftp 10.3.0.0.*
- **More... in the connection dialog.** Opens the session settings that
  are rarely needed: the SFTP server command above and the command run
  after login, with whether to wait for it. The command after login
  (`sendcommand`) existed before but could only be set in `sftpplug.ini`.
- **Dark dialogs when Total Commander is dark.** With TC in dark mode —
  always on, following Windows, or switched by hand — every dialog of the
  plugin opens dark too: caption, background, fields, lists, buttons,
  scroll bars, check boxes and group boxes. In light mode nothing changes.
- **Skip and Skip all for a file that cannot be downloaded.** In a copy of
  several files, a file the server will not hand over (no read rights, a
  broken link) asks whether to skip it, skip every such file in this copy,
  or cancel — Total Commander's own message offers only OK or Cancel, one
  window per file. A skipped file is noted in the log and nothing of it is
  left on disk. A move and a resumed download keep the plain error, as
  skipping would let Total Commander delete a source that never arrived.
  *From wesmar/sftp 10.3.0.0.*

### Fixes

- **Connection dialog.**
  - Alt+C went to the Auto/IPv4/IPv6 buttons and Alt+P to the "?" button,
    in every language, instead of the address and password fields.
  - The classic build no longer shows the PHP Agent's "Shell..." button
    and "TAR" box (they were there, greyed out); the session name takes
    the room.
  - The dark theme switched Total Commander's whole process to dark menus
    and scroll bars and left it so; the previous mode comes back when the
    plugin's last dialog closes.
- **[Imports] scans.**
  - A large FileZilla site list or PuTTY `.reg` export froze Total
    Commander when its folder was opened after a change: the file was
    read and parsed again for every session, and FileZilla's handling of
    duplicate names compared every site with every other each time. The
    file is now parsed once per change. A `.reg` export over 16 MB is
    refused.
  - A scan decrypted every saved KiTTY and FileZilla password only to note
    that the session has one. It only notes it now; the password is read
    when that session is connected.
  - A KiTTY session's password was read from the file in separate reads,
    so host and password could come from different versions of it.
  - A custom import path of a few hundred non-Latin characters was cut on
    reading back, and the session then opened the connection dialog
    instead of being checked.
- **Encodings and local paths.**
  - Some code pages "Other..." accepts (UTF-8 as 65001, UTF-7, the
    ISO-2022 and ISCII families, GB18030, symbol) failed every file
    operation: the folder listed, but nothing could be opened, copied,
    renamed or deleted. They work now, still refusing a name the code page
    would change; one from the settings file that Windows does not know
    falls back to the system code page.
  - With a local path of 260 characters or more, a failed download that
    was skipped left its partial file, an interrupted one did not resume,
    and an upload with Move kept its source with an error.
  - Through the plugin's ANSI functions (Total Commander before 7.5),
    names were cut to the low byte of each character; they are converted
    in the system code page.
- **Session names and the settings file.**
  - A session could be named like a folder of sessions ("a" beside
    "a/x"), and the folder went out of reach behind it; F6 did it after
    the overwrite question. Such a name is refused now.
  - Renaming a session in its dialog only in letter case did nothing and
    said nothing; a rename that failed for another reason went on and
    wrote a second session without its passwords. Case-only renames go
    through, and a failed one stops with a message.
  - Deleting a folder of sessions while the settings file could not be
    written left the sessions but removed their passwords and the jump
    host references to them. Those go now only with the session itself.
  - Exporting, importing and copying a session from [Imports] cut values
    at 2048 characters (a long post-login or SFTP server command). They
    are copied whole.
  - When another program held the settings file locked for more than five
    seconds, the plugin wrote without the lock and could lose what the
    other writer saved. That write now fails instead.
  - Settings in a profile folder whose name the ANSI codepage cannot write
    were not found: the folder is taken from Total Commander's
    COMMANDER_INI then.
- **Local files.**
  - F5 of a row of [Imports] or [Active Sessions] to a local folder
    replaced a file of the same name without asking, and reported success
    when nothing was written. It asks, and a write that fails (a full
    disk) is an error, also for session exports.
  - Each "overwrite?" between two sessions left an empty `sftp*.tmp` in
    the temporary folder.
- **Links and the home folder.**
  - A link or the home folder whose path did not fit opened the session's
    root as if it were the target. It is refused.
  - Any file or link named `~` was opened as the home folder; only the
    `~` entry the plugin adds at the root and in `/home` is.
  - Enter on a session whose last folder path is too long for the panel
    opens the session's root instead of a cut path naming another folder.
- **Connections and background transfers.**
  - A connection made from "[F7 = new connection]" without a session name
    was never kept: the panel stayed at the root, the SSH session stayed
    open until Total Commander exited, and each try opened another. It is
    now the Quick Connection, opened in the panel.
  - A background copy whose session the panel disconnected meanwhile
    failed for every remaining file, though its own connection was still
    open; for a session in a folder, that connection was never closed.
    It finds and closes its own connection now.
  - Disconnecting or replacing a session from a background thread (a
    session file dropped in a background copy) freed the panel's
    connection while the panel could still be listing on it. The panel
    closes it itself, once nothing of it is using the connection.
  - Copying or importing a session over one that is connected left the
    panel on the old host until the next reconnect. The replaced session
    is disconnected.
  - The owner and permission columns could show values from another
    folder after a search, and were kept for every folder ever listed.
    They are kept per listing, for the folders listed lately.
- **F6 with overwrite works on OpenSSH.** The overwrite flags of an SFTP
  rename reach only SFTP v5 servers; OpenSSH (v3) refused an existing
  target although the overwrite was confirmed. The plugin now uses
  OpenSSH's posix-rename, and on a server without it removes the target
  file first.
- **A long name no longer ends an SFTP listing.** An entry longer than the
  listing buffer (a Windows OpenSSH server with a long non-Latin name)
  ended the listing there without a word, so a delete or move of the
  folder missed what followed. The buffers hold any name now, and a
  listing that still cannot go on says so in the log.
- **Shell transfer mode.**
  - Replacing a file with a download could lose both copies: the old one
    was deleted, then the new one could not be moved in (an antivirus
    holding it) and was deleted too. The replace is one step now, and a
    failure keeps both. A file of the user's named like the temporary one
    is no longer deleted.
  - A raw upload whose size the server could not report was redone over
    base64, which starts by truncating the file; on a host without
    `base64` a correct upload ended empty. An unknown size is accepted.
  - One file that could not be read switched the whole session to the
    slow base64 path. Only base64 succeeding where raw failed does that.
  - On a host that allows no exec channel, folder creation, rename, copy,
    chmod and the existence check now run on the session's shell as
    transfers do; each upload asked about overwriting, renames answered
    "exists", F7 and chmod failed.
- **SCP-only mode.**
  - Large folders and long deletes: a command could run 30 s in all and
    stay silent 10 s; `ls -l` of a large folder, which prints nothing
    while it sorts, never listed, and deleting a large file was reported
    failed while it went on. The limit is now two minutes of silence, and
    Esc ends the wait.
  - Uploads keep the local file's modification time (scp -p), as do
    shell-mode uploads (`touch`).
  - The read-only attribute is set with `chmod` instead of reporting
    success for nothing.
  - A listing line the plugin cannot read is named in the log instead of
    left out silently.
  - A file name with a line break on a host whose terminal still echoes
    could make a failed delete look done: the end marker of every shell
    command is now sent split, so its echo never matches.
- **Text mode decides on the same bytes everywhere.** Whether a download is
  binary (a NUL byte) was judged on the first chunk, which is 57 bytes over
  base64 and almost 2 MB over SFTP: a log with a NUL further in was
  converted on one path and kept on another. Every path now looks at the
  first 64 KB.
- **The detailed log** shows SFTP listing lines in the session's encoding.
- **Jump host login.**
  - When the jump host did not list its login methods in time, only
    Pageant was tried: no key file, no password prompt. Every method is
    tried now, as for the target host.
  - A jump host asking for a second factor (a one-time code after the
    password) got an empty answer and could never be passed. Such
    prompts are put to the user, and time spent typing does not count
    towards the login timeout.
- **A password the server makes you change is saved like one from the
  dialog.** If Total Commander's password manager refuses it, that is
  reported instead of silently moving the password into the plugin's
  settings; a failed encryption no longer erases the stored value; the
  old manager entry is removed; a stored "password","passphrase" pair
  keeps its passphrase.
- **Imported passwords longer than 259 bytes** were put into the password
  manager whole but read back cut. They are not stored now and are asked
  for on connect, as the dialogs already refuse them.
- **Long settings are read whole.** Server, user, key file paths, jump-host
  fields, the post-login and SFTP server commands were read into 260-byte
  buffers: a long Cyrillic key path, saved complete, connected cut ("key
  file not found"). A key path too long for authentication is refused
  instead of cut.
- **Cancelling a connect** no longer shows "cannot connect" afterwards.
- **Post-login command:** its output shows without terminal colour and
  title codes, and starting it in "do not wait" mode is bounded in time.
- **More secrets wiped:** the buffer of the password prompt at connect,
  the proxy password prompt, the HTTP proxy request (no longer copied
  around while it grows), stored-secret and jump-host settings copies.
- **PHP Agent: a 0-byte file uploads again.** An empty file was sent
  straight to the final step without its `.part`, and the upload failed.
  *From wesmar/sftp 10.3.1.0.*
- **PHP Agent: a failed transfer is reported once.** Each failed file of a
  batch opened a dialog of its own, on top of Total Commander's, even
  after "Skip all". It now goes to the log, and Total Commander reports
  it. *From wesmar/sftp 10.3.1.0.*
- **Copying a session file into the plugin no longer opens the dialog
  for a new session.** A folder of sessions named with a trailing
  backslash, as Total Commander names the target of a copy, was not
  recognised as a folder and was connected to as a session; so was the
  target of a background copy. Closing the dialog let the import go on.
- **SCP-only downloads longer than 20 seconds no longer fail.** The stall
  timeout counted from the start of the transfer, so the first pause in
  the data after 20 seconds ended any larger download as "stalled".
- **An unreadable file no longer costs the local copy.**
  - Overwriting a local file from a remote one that cannot be read, in
    SCP-only and shell-transfer sessions, deleted the local file before
    the server said no. The download now goes to a file beside it and
    replaces the original only when complete.
  - Choosing Skip for a file that could not be read deleted the local
    file of that name even when the download had not touched it. Only a
    file the failed download wrote is removed now.
- **Resuming past 4 GB on the 32-bit plugin.** An SFTP upload resumed
  on a remote file over 4 GB wrote the rest at the wrong place and
  reported success, after which a move deleted the source; an SCP-only
  download over 4 GB failed. Offsets are 64-bit now, and a resume checks
  where it writes.
- **Shell transfers keep more of what they had.**
  - A resumed download whose fast path failed started over from zero,
    throwing away the part already there; it now continues where it was.
  - Text mode no longer converts line breaks in a file that turns out
    to be binary (UTF-16 text among them), as SFTP mode already did.
  - Downloads keep the server's modification time.
  - A terminal that still echoed commands could put a few junk bytes at
    the start of a base64 download.
  - Cancelling an upload while the server finished writing reported it
    done; a file name with a quote in it went into the SCP header with
    the quoting left in.
- **SCP no longer takes the end of a connection for "OK".** A server
  closing the channel in the middle of the protocol was read as a
  confirmation.
- **Shell transfers notice a refused file.** A download of a file the
  server would not let `cat` read was saved empty and reported done; an
  upload the server refused (no permission, disk full) was reported done
  too, and a move then deleted the local file. Both now fail.
- **File names in every encoding survive.**
  - In a UTF-8 session, a name with bytes that are not UTF-8 (written by
    an older program in another codepage) was shown with "�" and could
    not be opened, renamed or deleted. It is now kept byte for byte.
  - In a Shift-JIS, GBK or Big5 session, a character whose second byte
    is the code of `\` was broken by the path handling.
  - A server's locale named `en_US.utf8` (rather than `UTF-8`) was not
    recognised as UTF-8, and a server without a shell (an SFTP-only
    account) was saved as using the Windows codepage; it is now taken as
    UTF-8 for the connection, and nothing is saved.
  - One line in `sftpplug.ini` that is not UTF-8 made the plugin read the
    whole file in the Windows codepage and save it back that way,
    garbling every session name in another language. Only that line is
    read that way now.
  - A `cd` through the quote command to a path too long for the buffer
    is refused instead of being cut to another folder.
- **SCP-only listings show every name as it is.**
  - Spaces at the start or end of a name were dropped, so the file could
    not be opened or deleted; a backslash followed by three digits was
    read as a character code ("a\101b" listed as "aAb"); a name with
    " -> " in it was cut there although it was no link; device files
    came out with a shifted date.
  - A name with a line break in it could show up as two entries, the
    second one made up and pointing at another file. Where the server's
    `ls` is GNU, it is now asked to escape such characters and the plugin
    decodes them, so one entry is one file.
  - A listing that did not finish is no longer shown as if complete.
- **SCP-only and shell transfers on more servers.**
  - The shell is switched to `/bin/sh` first, so a csh, tcsh or fish
    login shell no longer breaks the commands.
  - A base64 download from macOS, which writes the whole file on one
    line, was cut short; the output is now wrapped.
  - A large base64 download no longer fails after 90 seconds, and a
    copy or move of a large file on the server is no longer reported
    failed while still running.
  - Creating a folder no longer fails because the server wrote a banner
    to stderr, and it gets the session's folder mode.
  - The home folder is found where the shell prints a prompt first.
- **SCP-only listings ignore the user's `ls` settings.** An `LC_ALL`, a
  `TIME_STYLE` or a `BLOCK_SIZE` in the server's environment changed the
  dates or sizes `ls` printed, and the listing came out wrong.
- **The quote command reports failure.** "quote" in Total Commander's
  command line reported success for a command that failed, and failure
  for one that worked. A mode for chmod that is not plain octal digits is
  refused.
- **A background transfer of an [Imports] session no longer opens the
  connection dialog.** It looked for the session in the own list, found
  nothing and asked for a new one; it now connects the way Enter on it
  does, with the password the panel's connection has.
- **Session names are checked wherever a session gets one.** The
  connection dialog, F5/F6 in the plugin, a session file dropped on it
  and a copy from [Imports] all refuse a name that would not come back
  the same from `sftpplug.ini`, or would collide with something else
  there: control characters, a backslash, `$$`, a space at either end, a
  leading `[`, the plugin's own sections (`proxy`, `proxy2`…,
  `Configuration`, `Imports`), or a place inside another session, where
  the session could never be reached. Brackets inside a name, as in
  `web [old]` or a PuTTY session `prod [eu]`, now work: the name used to
  end at the first `]` and the settings were lost or mixed up.
- **`sftpplug.ini` keeps what it is given.**
  - A line break in a value — an imported session name, say — could add
    a line of its own to the file, any setting at all; such a write is
    refused.
  - A value in quotes (a server command like `'/usr/lib/sftp-server'`)
    lost its quotes on the next read.
  - Saving replaced the file, losing its permissions, and turned a
    symbolic or hard link into a plain file. It now keeps both.
  - With about 200 sessions, a new proxy record could get the number of
    one that exists and overwrite it; the list of sections is no longer
    cut short.
  - Moving sessions on a file that cannot be written deleted them from
    their old place anyway. They now stay where they were, and the error
    is reported.
  - A rename that changes only the case of a name did nothing.
- **The help matches the plugin.** The pages on shell commands, shell
  transfers and resuming described commands and steps the plugin does not
  use (a `dd` method, `base64 -w 0`, 3-byte alignment, a question from
  Total Commander on a size mismatch); authentication, sessions, security,
  proxy, import and settings pages and the README are corrected on method
  order, password storage, proxy with a jump host, imported passwords and
  the debug log. The password field's help showed the two-password form
  the wrong way round: it is `"LoginPassword","KeyPassword"`, as the plugin
  reads it.
- **Dialogs and messages.**
  - A password too long to be kept is no longer cut without a word: the
    password fields take at most 259 characters, and one that still needs
    more than 259 bytes (letters outside the Latin alphabet) is refused on
    OK with a message.
  - Keyboard shortcuts in the connection and jump-host dialogs no longer
    repeat in 13 of the 15 translations (two controls on one letter, so the
    second could not be reached); Japanese and Chinese use the "(&C)" form
    with a Latin letter, as their own programs do, and "&(Pageant)" no
    longer puts the shortcut on the bracket.
  - A jump host whose referenced session is missing shows why, with empty
    fields, instead of the session's unused own settings labelled as the
    missing session's.
  - A PHP Agent or LAN Pair session opened in the classic build is truly
    read-only: the proxy list, proxy settings and "Change password..." are
    closed too, since they save on their own.
  - Jump-host errors (name not found, no connection, handshake, login,
    tunnel) are translated.
  - Long texts taken from the plugin's resources (the F1 help without a
    language file) come whole and in UTF-8, so dashes and accents no longer
    break; language files, the help page, the INI template, `sftp.php` and
    `pageant.lnk` are found in a plugin folder whose name the system
    codepage cannot spell.
- **An upload is finished only when the server has closed the file.** The
  SFTP upload reported success with the remote file still open and closed
  it later without waiting, so the server could keep it open, and an error
  in the last writes, which shows in the answer to the close, went unseen.
  It now waits for that answer, reports a failed close, and sets the time
  and permissions on the closed file.
  *Found by numbereleven-a.*
- **libssh2: no double free on a corrupt stream.** When decryption,
  decompression or a bounds check failed, the packet buffer was freed and
  freed again when the session ended — a server sending garbage could
  crash Total Commander. Fixed at all five places in our patch series
  (numbereleven-a fixed two). Also from there: a failed symlink or
  realpath request took the request number for the error code.
- **Copying between two sessions keeps the bytes.** With text mode on
  automatic and Unix line breaks set, a text file copied from one server to
  another arrived with Windows line breaks: the download converted it by
  its name, the upload from the temporary file did not convert it back.
  The copy is now binary on both legs. *Found by numbereleven-a.*
- **Smaller fixes, from a review of numbereleven-a's fork.**
  - Copying or renaming a session reads its keys and values whole, however
    long; a cut list would have lost keys, and a move then deleted the
    original.
  - Renaming without overwriting refuses when the server cannot say
    whether the target exists, and in shell mode a broken link counts as
    existing; both used to be replaced without asking.
  - A shell-mode resume onto a remote file larger than the local one, or
    of unknown size, is refused as in SFTP mode instead of starting over.
  - The shell terminal opens with echo off, also on hosts without `stty`.
  - The "quote" command's exit status is read after the command has
    ended; SCP-mode listings wait on the connection instead of sleeping
    and keep long lines (link targets) whole.
  - Changing a session's host or port in the dialog drops its stored host
    key fingerprint, as for the jump host, instead of warning on the next
    connect that the key changed.
  - Setting a file's time keeps its access time.
  - A symlink target too long for the path is refused instead of cut to
    another folder.
  - SFTP start-up waits in the direction the connection is blocked in;
    the jump-host socket is closed when its session cannot be created;
    password buffers are wiped after use.
- **Session import fixes.**
  - PuTTY, KiTTY, WinSCP: "use Pageant" was taken from agent forwarding,
    so a Pageant user got a password prompt; it now comes from "Attempt
    authentication using Pageant", on unless turned off.
  - WinSCP: a session inside a folder could not be opened.
  - An IPv6 address with a port other than 22 is written in brackets;
    without them the port became part of the address.
  - KiTTY: a password stored with the other of its two keys decoded to
    garbage, which was sent as the password. A password with letters
    outside English is converted from the system codepage, as the plugin
    keeps passwords in UTF-8.
  - FileZilla: two sites of the same name in one folder, or differing only
    in case, were one entry; the later one is now listed as "name (2)".
  - OpenSSH: an `Include` loop stops at once instead of being read again
    sixteen levels deep.
  - Session folders are walked at most 32 levels and 20000 entries deep,
    and a junction or link to a folder is not followed.
  - SecureCRT: a "Firewall Name" or tunnel session that points outside its
    folder is not read.
  - The import cache and a portable `WinSCP.ini` are read whole, however
    many sessions they list.
- **Session settings read back what was saved.** A stored password longer
  than the read buffer — a long one, or any password once encrypted — no
  longer loads empty. A file or folder mode that is not an octal number no
  longer becomes 0 (no rights at all) but stays at 644 or 755, in the INI
  and in the dialog. A jump-host port outside 1–65535 falls back to 22.
- **Cancelling "Other..." codepage keeps the old one.** Closing the prompt
  or typing something Windows has no codepage for left the session with an
  unusable codepage; the saved one now stays.
- **Long local paths and network folders.** A local path of 248 characters
  or more, where creating a folder already fails, gets the long-path
  prefix; a network path gets its own `\\?\UNC\` form instead of a prefix
  Windows does not resolve, and a path that already has one is left as it
  is.
- **Basic proxy login no longer reads past the user name.** Encoding the
  proxy credentials read one or two bytes beyond their end.
- **Number-to-text conversions in the dialog check the buffer size.**
- **Deleting a proxy record reported the result the wrong way round.**
- **An upload is no longer taken for a session file.** After a
  connection to a session was closed, a `.ini` file copied into one of
  its folders could be read as a session to import, creating a new
  session from it, or fail with an import message.
- **A session file copied onto a session of the same name asks to
  overwrite it** instead of failing with "Error uploading file". The
  replaced session is disconnected, and passwords the file does not
  bring leave the password manager. An upload into a session not yet
  open in the copying thread no longer fails the same way.
- **A background transfer ending no longer drops other connections.**
  When one of several background copies on a session finished, it closed
  every connection of that session: the other copies still running and
  the panel's own, which then had to reconnect. Each now closes only its
  own. A background copy also gets the jump host and proxy passwords the
  panel's session already has, instead of asking for them again.
- **Thread fixes for background transfers.** SSH library start-up, the
  language strings, the server list, directory listing state and the
  text-mode setting were shared between threads without protection; a
  listing left open across a reconnect could close a handle of the new
  connection. A language change in Total Commander no longer overrides
  the language chosen in the plugin.
- **The connection dialog keeps its width.** Two check boxes stacked
  beside the taller System list were taken for one row, their widths
  added up, and the dialog grew to about twice its width — more on every
  re-layout.
- **Hidden controls stay hidden in the dark theme.** A hidden check box or
  group box that was enabled or relabelled got marked visible and showed
  up on the next repaint, after Alt+Tab say: the password manager check
  box under Change password..., the LAN Pair group title over the
  permissions group.
- **A wrong SFTP server command is named as the cause.** When the command
  set under More... did not start SFTP, the error suggested turning on SCP
  for everything; it now points at the command.
- **SCP text-mode download no longer overruns its buffer.** With text mode
  on, a file dense with line breaks grew past the read buffer as LF became
  CRLF and was written beyond it in memory — and the content comes from the
  server. The converted text now goes to a buffer of its own.
  *From wesmar/sftp 10.3.0.0.*
- **Text-mode uploads over SCP announce exactly what they send.** The size
  in the scp header was the file size minus its CRs, but a CR without an LF
  after it stays, and a CRLF split between two reads kept its CR; the
  server then waited for bytes that never came or took the closing byte as
  file data. The size is now counted by the same conversion that sends the
  file, and a mismatch fails the upload instead of leaving scp out of step.
  *From wesmar/sftp 10.3.0.0.*
- **"Resume" on a text-mode file starts the transfer over.** The offsets
  of a converted file differ on the two sides, so it cannot be continued
  from the middle; Total Commander still offers "Resume", and picking it
  now sends the whole file again instead of failing, in both directions.
- **Text mode also in shell transfers.** Files sent or fetched through the
  shell (dd / base64: the forced shell mode, and before this release every
  SCP-only resume) kept their line endings as they were, while SFTP and
  SCP converted them. They are now converted the same way, and the size
  check compares with the converted size.
- **SOCKS proxies refuse what they cannot send instead of sending
  something else.** A SOCKS5 proxy's "no acceptable method" was never
  recognised, a user name or password over 255 bytes was cut short, and a
  host name over 255 bytes was cut into a different name; these now end
  with an error. Reply bytes are read as unsigned, an IPv6 address is never
  looked up in DNS, and a SOCKS4 request is checked against its buffer.
  Proxy credentials are wiped from memory once sent.
  *From wesmar/sftp 10.3.0.0.*
- **PuTTY keys are converted on OpenSSL, and more of them load.** An
  encrypted key in PuTTY's format 2 never loaded: its MAC was checked over
  the encrypted data, while PuTTY computes it over the decrypted one. About
  one Ed25519 key in 256 was refused because its secret was stored shorter
  than 32 bytes. The Argon2 settings of a format-3 key were taken as given,
  so a crafted file could demand any amount of memory and time; they are
  now capped. Every key is now rebuilt and checked by OpenSSL, the MAC is
  verified for unencrypted keys too, and the decrypted key is wiped from
  memory. *From wesmar/sftp 10.3.0.0.*
- **A PuTTY key refused for its Argon2 settings or for not matching itself
  is named as such** instead of a general conversion error.
  *From wesmar/sftp 10.3.0.0.*
- **Shell and SCP-only listings survive modern prompts.** An escape
  sequence was skipped up to the next letter "m", so bracketed paste
  (`ESC[?2004h`) swallowed the marker the listing waits for, and systemd's
  OSC 3008 records (Ubuntu 25.10, Fedora 42) left fragments in the lines.
  Control sequences are now parsed as ECMA-48 defines them, UTF-8 text is
  kept, and only real octal escapes are decoded.
  *From wesmar/sftp 10.3.0.0.*
- **Shell transfers: resume, empty files and missing files.** A resumed
  base64 upload rounded its starting point down to a multiple of three and
  appended from there, writing one or two bytes twice. An empty file was
  never created on the server, yet reported as uploaded — and on a move the
  local file was then deleted. A file the server could not read came down
  as an empty file; base64's exit status now fails it.
  *From wesmar/sftp 10.3.0.0.*
- **An upload no longer overwrites a file Total Commander did not know
  about.** When TC had not listed the target folder — a background copy, a
  subfolder never opened — it passed no "file exists" flag, and the upload
  replaced the server's file without asking. The server is now asked first,
  and TC asks the user. *From wesmar/sftp 10.3.0.0.*
- **Quick Connection is not advertised on the LAN.** The name was checked
  against "Quick connect" and its Polish form, while the entry reads "Quick
  Connection" or its translation, so LAN Pair discovery announced it like a
  saved session. *From wesmar/sftp 10.3.0.0.*
- **A post-login command's output keeps its non-English ending.** Trimming
  the output treated UTF-8 bytes as blanks and cut letters off the end of
  each line, and the progress text shown while the command ran was empty.
  *From wesmar/sftp 10.3.0.0.*
- **Smaller hardening.** A PHP Agent listing entry whose name does not fit
  is left out rather than shown cut, as a name that leads nowhere. A stored
  password in the old numeric format with a value above 255 is refused
  instead of decoded into a wrong byte. *From wesmar/sftp 10.3.0.0.*
- **LAN Pair: faster pairing key and Unicode profile paths.** The pairing
  key is derived with Windows' own PBKDF2, about four times faster and with
  exactly the same result, so existing pairings keep working. The secrets
  folder is found through the wide API, so a Windows profile whose path
  has characters outside the system codepage works.
  *From wesmar/sftp 10.3.0.0.*
- **Long file names no longer crash the text-mode check.** Matching a name
  against the text-type list copied both into fixed buffers of 260 and
  1024 characters, and a longer one ended the process. Matching now works
  on the strings themselves, and letters beyond ASCII match regardless of
  case. *From wesmar/sftp 10.3.0.0.*

### Changes

- **Unused code removed, more tests.** About 500 lines of functions,
  constants and branches nothing called anymore are gone, and comments that
  told the code's history now say what it does. New tests: a text file
  copied between two sessions, the INI reader and writer (brackets in
  section names, refused line breaks, quoted values, long values and long
  section lists, a stray non-UTF-8 byte), the KiTTY password check, and the
  keyboard shortcuts of every dialog in every language.
- **PHP Agent and LAN Pair under test.** The integration tests run the
  extra build against the PHP Agent bench in Docker (PHP 8.3 and 7.4):
  uploads including an empty file, downloads, resume, rename, folders. The
  LAN Pair handshake (RFC 9382 test vector) and encrypted session are
  covered by unit tests. *Tests from wesmar/sftp 10.3.1.0.*
- **Dialogs sharp on every monitor and sized to their text.** The plugin's
  windows (connection, proxy, jump host, properties, download error, LAN
  Pair search) are per-monitor DPI aware: on a second screen with another
  scale they are drawn at its DPI instead of being stretched, and they lay
  out again when moved there. Each dialog grows until the loaded
  language's texts fit, so labels no longer end cut off ("Use SSH agent
  (Pageant" and many translated ones), group boxes share one right edge and
  "Jump..." stays inside the window. On Windows 11 they get rounded corners
  and the Mica caption. A layout test renders every dialog in every
  language and checks for clipped, overlapping or outside controls.
  *From wesmar/sftp 10.3.0.0.*
- **Release packaging.** A package missing any of its parts fails the
  build instead of being published without it; language files are stored
  under `language/` with a forward slash, as ZIP specifies. Each release
  also carries the debug symbols of its build (`-pdb.zip`, for crash
  reports) and `SHA256SUMS` for checking a download. The workflow's actions
  are pinned to exact commits, the checkout fetches only the OpenSSL and
  libssh2 sources, and the compiler's extra security checks (`/sdl`) are
  on.
- **"Protect password with password manager" without "(TC>=7.5)".** Every
  Total Commander the plugin runs in is newer than that.
- **No more argon2 library.** Argon2 for PuTTY keys of format 3 comes from
  OpenSSL (3.2 and later), which the plugin already carries; the separate
  argon2 submodule and its build step are gone.
  *From wesmar/sftp 10.3.0.0, on OpenSSL 3.5 here.*
- **UTF-8 and UTF-16 are converted by Windows itself.** A name with bytes
  that are not valid UTF-8 — a file on the server named in another
  encoding — shows whole, with `�` in their place, instead of being cut at
  the first bad byte. The bundled ConvertUTF library is gone.
  *From wesmar/sftp 10.3.0.0.*
- **Unit tests.** The PPK converter (against 20 puttygen keys), text-mode
  line endings, the terminal filter, wildcard matching, stored-password
  encryption and the LAN Pair key are covered by unit tests, run on every
  release build before the plugin is built. *From wesmar/sftp 10.3.0.0.*
- **Faster uploads through the shell.** When the shell takes base64 spread
  over several lines, each command now carries 48 KiB instead of 1 KiB; a
  six-byte probe asks first, and a shell that does not take it keeps the
  single-line 1 KiB form. The command's end marker is sent split, so a
  terminal that still echoes cannot pass the echo for the end.
  *From wesmar/sftp 10.3.0.0.*

## 10.0.2.3 — 2026-11-15

### Features

- **Any characters in session names, folders, hosts, users and key
  paths.** The plugin used to keep them in the Windows codepage, so a name
  in another script — Chinese or Greek on a Russian Windows, say — came out
  as question marks. Now the session list, the connection dialog, the
  status line and the password manager take any characters, and a key file
  opens from any folder. A user name or password with non-English
  characters now reaches the server in UTF-8, as SSH expects; one that was
  set up to work as system-codepage bytes may need to be entered again.

### Changes

- **`sftpplug.ini` and the import cache are stored in UTF-8.** The plugin
  reads and writes its own INI files itself instead of through the Windows
  INI functions. An existing file in the system codepage is read as before
  and saved as UTF-8 on the first change. Older plugin versions still read
  the file, but show non-English characters in it garbled. A session file
  exported with F5 and copied back in is now read with its non-English
  characters intact.

### Fixes

- **A file the server refuses to read leaves no empty copy.** A download
  created the local file first and only then opened the remote one, so a
  file without read rights (`chmod 000`) failed with an error and still
  left an empty file behind — and when overwriting, the local copy was
  already truncated. Over SFTP and SCP the remote file is now opened first,
  and the local file is not touched when that fails. With "SCP for
  everything" and shell transfer the refusal shows up only after the local
  file exists: the empty file is removed again, but a local copy being
  overwritten is still lost there.
- **An SCP download of an unreadable file no longer blames scp.** "Use
  SCP for data transfers" showed "Cannot execute SCP ... make sure that
  SCP is installed" for a file without read rights. When the file is
  there, the refusal is now a status line; the dialog stays for a scp
  that really does not run.
- **"SCP for everything" lists non-ASCII names on servers without a UTF-8
  locale.** `ls` on a terminal printed such names as `test???`, and those
  files then could not be opened or deleted. Its output now goes through a
  pipe and the names arrive as they are.
- **"SCP for everything" no longer reports a failed delete as done.** A
  file that was not there passed for deleted (`rm -f`); now the error comes
  back. The error line of `ls` for a missing directory is no longer read as
  a file entry, so such a directory fails to open instead of showing a
  bogus entry.
- **A password the master password could not store is kept.** When Total
  Commander refused to save a session or proxy password in its password
  store — it cannot create `wcx_ftp.ini` when it keeps its settings in a
  read-only `Program Files` folder — the plugin dropped the password
  silently. It now says so and stores the password encrypted in
  `sftpplug.ini`. The help page on security describes the cause and fix.
- **A PuTTY key is no longer written to disk unencrypted.** To log in with
  a `.ppk` key the plugin used to convert it into a temporary PEM file in
  `%TEMP%` and delete it afterwards — a crash in between left the decrypted
  private key there. The key is now converted and handed to the SSH library
  in memory only, and every key file is read the same way.
- **Imported sessions keep non-English names and paths.** Sessions from
  SecureCRT, FileZilla and `~/.ssh/config` with Cyrillic (or other
  non-English) names, hosts or key paths were shown and stored garbled, and
  a custom import location in such a folder was not read. PuTTY, KiTTY and
  WinSCP sessions read the same characters correctly too, including
  locations in folders outside the system codepage.
- **A remote path too long for the plugin is refused instead of cut.** A
  path beyond about 1000 bytes — 1000 Latin letters, fewer in other
  scripts — used to be cut short silently, and the operation, a delete
  included, went to the shorter path. A file name from the server too long
  to show is left out of the list instead of appearing cut, as a name that
  leads nowhere.
- **Files in folders outside the system codepage are read.** An INI file
  with a session copied into the plugin from such a folder was refused as
  unreadable, and the PHP Shell history was not kept when the Windows
  profile folder had such a name.
- **SecureCRT key paths with its own placeholders are found.** SecureCRT
  writes `${VDS_USER_DATA_PATH}`, `${VDS_SSH_DATA_PATH}` (the Documents
  folder) and `${VDS_CONFIG_PATH}` (its configuration folder) into key
  paths, so one configuration works on any system. They were left as they
  were, and the key was never found.
- **F3 and F5 on a proxy in `[Proxies]` show and copy the record, and a
  copied record goes back the same way.** They used to end in "Error
  downloading file". The record comes out as an INI snippet without the
  password; copying such a file into `[Proxies]` adds it, or says the same
  proxy is already there.
- **A key passphrase with non-English letters opens keys from Windows and
  from elsewhere.** puttygen on Windows encrypts a key with the passphrase
  in the system codepage, tools elsewhere in UTF-8. The plugin now tries
  the passphrase as typed and, when that does not open the key, in the
  system codepage — for PuTTY and OpenSSH keys alike. Keys made with such a
  passphrase on Windows had stopped opening in 10.0.2.3-rc1.

## 10.0.2.2 — 2026-11-03

### Features

- **`~/.ssh/config` as an import source.** `[Imports]\[OpenSSH]` lists
  every host of the OpenSSH client config and connects with what it says,
  resolved as `ssh <host>` would: `HostName`, `Port`, `User`,
  `IdentityFile`, defaults from `Host *` and other patterns, `Include`,
  and `ProxyJump` with one hop as the jump host. The config stays the
  place the settings live; nothing has to be copied. `ProxyCommand` and
  jump chains are refused, `Match` is skipped.
- **Imports follow their sources without `[Refresh]`.** Opening a source
  folder notices when the program's files or registry keys changed since
  the last look — and on the first look after Total Commander starts — and
  re-reads them, in the auto-detected location and in the ones added by
  hand. A location that has gone missing keeps its sessions, as before. A
  host key confirmed for an imported session survives the re-read while
  the host stays the same.
- **Owner, group and permissions in the file list.** The plugin now
  offers custom columns — owner, group, permissions (`rwxr-xr-x`), octal
  (`0755`) and link target — and a default view with the first three next
  to size and date, which Total Commander picks up on its own. Values come
  from the directory listing in both SFTP and SCP mode; a server that
  sends no names shows numeric ids.
- **Alt+Enter on a remote file shows its properties**: path (with the
  link target), owner, group, permissions, size and date from the
  listing, and below them the server's own `stat` reply. Without a shell
  on the server, the SFTP attributes stand in for it. Translated into all
  languages.
- **Host key fingerprints are SHA256**, in the form OpenSSH prints, so
  they can be compared with `ssh-keygen -lf` on the server. The
  confirmation shows MD5 below it. A fingerprint stored by an earlier
  version (MD5) still matches and is rewritten as SHA256 on the next
  connection, without asking. The same for jump hosts.
- **Imported sessions that go through a jump host now come with it.** A
  WinSCP tunnel, a SecureCRT session firewalled through another session,
  and a PuTTY session using "SSH to proxy and use port forwarding" import
  with the jump host filled in — connect straight from `[Imports]` or copy
  with F5. The jump host's password is asked for on connect, as is the
  target's. Still refused: a jump host that itself goes through a proxy or
  another jump host, a WinSCP tunnel combined with a proxy, and
  command-driven proxies (Telnet, local command).

### Fixes

- **"Log full directory listings" works in SCP mode**: the raw `ls -la`
  lines go to the log window, as the server's long entries already did in
  SFTP mode.
- **SCP mode: names with spaces or quotes are listed as they are.** GNU
  `ls` writing to a terminal wraps such names in quotes (`'a b'`), which
  then appeared in the panel and led nowhere.
- **SCP mode shows dates and permissions.** The listing kept only names
  and sizes, so every row had an empty date. Dates now come from `ls`
  run in English and UTC, whatever the server's locale and time zone, and
  the permissions reach Total Commander as they do in SFTP mode.
- **Uploads no longer spin a CPU core while waiting for the server.**
  When the connection could not take more data yet, the plugin polled the
  socket in a tight loop instead of waiting for what libssh2 was actually
  waiting on.
- **A one-time code is not reused as the password.** With two-factor
  login, an answer to a verification-code prompt was kept as the session
  password and sent again on a reconnect or a background transfer. Only
  answers to password prompts are kept now.
- **Symbolic links show as links in SFTP mode too**, instead of with the
  length of their target as a size.
- **Changing permissions with Alt+A works.** The command went out with
  the path in Windows form, failed on the server, and was reported as
  done. Over SFTP the mode is now set through the protocol, so it also
  works on servers without a shell; SCP mode runs `chmod` and reports its
  failure.
- **A jump host with no saved password now asks for one** instead of
  failing the login without a word.
- **An idle connection is no longer dropped by a router or firewall in
  between.** The plugin turns on TCP keepalive for the server socket and
  the jump host socket, so the link stays open after a minute of silence.

## 10.0.2.1 — 2026-11-02

### Features

- **An imported session that needs a proxy or a bastion no longer
  connects without one.** Sessions arriving from SecureCRT, PuTTY,
  KiTTY, WinSCP and FileZilla carry only the fields the plugin can
  reproduce, and a proxy, jump host or tunnel was not among them — so a
  session that reached its host through one connected **straight to the
  target** instead, which looks like success whenever the target also
  answers from outside. Such a session now says what is missing and
  refuses to connect or to be copied into your own list. `F3` still
  shows its settings: the file it opens names the missing route, and the
  plugin refuses to import that file back.

- **An HTTP or SOCKS proxy from PuTTY, KiTTY, WinSCP, FileZilla or
  SecureCRT comes along when the session is copied.** FileZilla keeps one
  proxy for the whole program, so it comes along with every site that
  does not bypass it. SecureCRT keeps its proxies as firewall records; a
  session that tunnels through another SecureCRT session, or names a
  record that no longer exists, is still refused. `F5` from `[Imports]` into your own list
  points the new session at a matching entry in `[Proxies]`, reusing one
  with the same type, address and user name or adding one. Copying it
  out to a file writes the proxy into the file, and dropping that file
  back onto the plugin resolves it the same way. The proxy password stays
  behind and is asked for on the first connection. Connecting straight
  from `[Imports]` still refuses, and now says that `F5` brings the proxy
  along. Jump hosts and tunnels are still refused.

- **The help is one HTML page instead of a CHM.** The Help button now
  opens `SFTPplug-help.html` in your browser, and `Ctrl+F` searches
  every topic at once — the whole manual is a single page. This also
  ends a long-standing annoyance: a CHM that arrives inside a downloaded
  ZIP is blocked by Windows and opens blank, which is exactly how this
  plugin reaches people. Microsoft withdrew the only CHM compiler years
  ago and never replaced the format; a page in the browser is what the
  category turned into.

### Fixes

- **A malicious server can no longer attack the plugin through its SSH
  library.** libssh2 1.11.1, which the plugin is built on, had ten flaws a
  server could trigger. The worst, an out-of-bounds write while reading a
  packet's length (CVE-2026-55200), could let it run code on your machine;
  another tied up the CPU before any login (CVE-2026-55199). Some needed
  nothing more than connecting. libssh2 has fixed them but not yet
  released a version with the fixes, so the plugin carries the same
  backports Debian ships for 1.11.1.

- **The PHP Agent help now says how the password really travels.** It
  claimed every request was signed and the password never crossed the
  network. In fact the plugin sends the password in a header of every
  request, so only HTTPS protects it; over plain HTTP anyone on the path
  can read it and reuse it. The help, the README and `sftp.php` itself
  now say so and ask for HTTPS. They also say plainly that PHP Shell is
  not held to the agent's folder — it runs any command as the web server
  user — and `sftp.php` gains `AGENT_ALLOW_SHELL`: set it to `false` and
  the password gives file access only. It stays on by default, so
  existing setups keep working.

- **The PHP Agent can no longer be walked out of its folder.** A link
  inside the folder pointing elsewhere let an upload, a new folder, a
  rename or an unpacked archive land outside it, and a folder download
  pack files from outside; a neighbouring folder whose name merely began
  with the same letters (`html2` next to `html`) also passed the check.
  Deleting or renaming a link now acts on the link, not on what it points
  to, and the agent's own folder can no longer be removed — removing it
  with its contents used to take `sftp.php` along. Anonymous `PROBE`
  answers only what connecting needs, error replies no longer carry
  server paths, and a replaced file keeps its old content until the new
  one takes its name. Upload the new `sftp.php` (agent 1.0.2) to get
  these.

- **PHP Agent files land where the panel shows them.** With a port in
  the agent's URL (`http://host:8083/sftp.php`) the plugin took part of
  the URL for a folder, so every upload went into extra folders named
  after the port and the script, while the panel still looked like the
  top folder. A folder that does not exist was also shown with the top
  folder's contents instead of an error. And names with non-Latin
  letters were sent in the Windows code page instead of UTF-8: such a
  file arrived under a garbled name, and one put on the server by other
  means could not be opened. A name that began with the server's name
  or the script's (`example.com.zip`, `sftp.php.bak`) lost that part on
  the way, so the operation reached another file or none.

- **New folders appear on a PHP Agent with TAR stream on.** `F7`
  reported success without creating anything, and the empty folders of
  a copied tree were left out, since the archive carries files only.

- **Uploading folders into the PHP Agent's top folder with TAR stream
  on works.** The agent refused to unpack an archive into its own root
  and answered every such upload with an error.

- **An upload through the shell no longer claims to have worked when it
  did not.** Each piece of the file was counted as written the moment the
  server answered anything at all, so a missing tool, a read-only folder
  or a full disk still read as success — and an upload that was really a
  move then deleted the local original. The server's own answer is now
  read, and the size it ended up with is compared against what was sent.

- **A move and a cross-server copy ask before replacing a file.** Both
  went ahead silently: the destination was truncated without Total
  Commander getting the chance to ask, and a move destroyed the source on
  top of that. The check behind the question now treats a name as free
  only when the server says so outright: a check that could not run —
  a channel refused, permission denied — no longer reads as "no such
  file", a name with non-Latin letters on a shell-only server is no
  longer looked up encoded twice, and a PHP Agent destination is checked
  at all.

- **A file name can no longer run commands on the server.** On servers
  the plugin drives through a shell, the file's name went into the
  command line unquoted, so a name containing a semicolon or a backtick
  was read as syntax rather than as a name. Downloading such a file ran
  whatever it spelled out. Names are now quoted, as they already were
  everywhere else.

- **Deleting on such a server reports what really happened.** The shell
  echoes back the command it was given, and the plugin was reading that
  echo instead of the result — so a deletion the server refused was
  reported as done and the file quietly stayed. The same false success
  reached moves, which then looked like copies.

- **A deletion is refused outright when the path names no single file.**
  An empty or degenerate path — `/` among them — is rejected before any
  command is built, rather than handed to a shell that would take it
  literally.

- **F6 moves the file instead of copying it, in both directions.** The
  transfer ran and the original stayed where it was: the plugin was told
  this was a move and never acted on it, on downloads or on uploads.
  Each side of a move is removed by whoever owns it, and the plugin owns
  the far side of both — the file on the server when you move from it,
  the file on your disk when you move to it. If it cannot be removed,
  that is now said out loud rather than leaving you to notice the file
  twice. A move you resume keeps its source, since part of the result
  was there before and nothing vouches that it matches; the status line
  says so. Affects every server type, and has since the first release of
  the original plugin.

- **Copying a file within one session copies it.** Copying to another
  folder or name on the same server — `Shift+F5`, or `F5` between two
  panels open on the same session — renamed the file instead, so it was
  gone from where it had been. SFTP and PHP Agent sessions now copy it
  through this machine, since neither server offers a copy of its own;
  shell-only servers keep using `cp`; LAN Pair refuses rather than move
  the file.

- **LAN Pair: resuming and renaming are safe.** A resumed download wrote
  past the end of the partial file, leaving a gap of zeros, and a resume
  that failed deleted the partial file it was continuing. Renaming onto a
  name already taken replaced that file without asking; it now asks, as
  on other servers — provided both machines run this version, since an
  older peer still replaces. Moving a file up to a LAN Pair peer now
  takes the local file away, as it does elsewhere.

- **Removing a folder on a shell-only server removes only an empty
  one.** The plugin used `rm -rf` there, where SFTP servers refuse a
  folder that still holds files. Total Commander deletes the files
  itself first and relies on that refusal to keep anything that was
  skipped or failed — so after `F6` on a folder, or `F8` with a file
  answered "skip", those files were wiped along with the folder.

- **PHP Agent: an upload no longer takes up a leftover `.part` file
  unasked.** A `.part` left by an earlier upload was continued even
  without Resume — splicing its start, possibly from another file, onto
  this one, or at equal size turning it into the file without a byte
  sent. It is now continued only when you choose Resume. Renaming a file
  to the same name in other letter case on a Windows or macOS server no
  longer deletes it. Re-upload `sftp.php` to pick up the second fix.

- **A download that keeps breaking off at the same point gives up.** The
  automatic resume after a dropped connection retried for as long as it
  failed, so an error striking at one spot every time held the copy
  forever; it now stops once a retry adds nothing. And a command run
  through the shell — a rename or a copy on a shell-only server — that
  timed out before finishing no longer passes for a success.

- **The public-key field is labelled for what it is now for: an OpenSSH
  certificate.** Since the move to OpenSSL the public half of a key is
  derived from the private key file, so the field asking for "Public key
  file (*.pub)" invited a file the login does not need — and a private
  key put there was ignored. It now reads "Certificate (*-cert.pub),
  optional", in the session and jump-host dialogs alike, and the file
  picker looks for certificates first.

- **Logging in to a server that takes keys only says what is missing.**
  With no key to offer, the login used to end without a word; it now
  says that the server accepts only a key and the session has none. In
  "Use SCP for everything" mode the plugin did not even ask the server
  which logins it takes, and offered a password prompt the server would
  never accept — it now asks whenever no key or password is set. And a
  private key entered in the public-key field is used to log in, instead
  of being passed over.

- **Connecting to a server without SFTP ends, and says what to do.** A
  host that offers only a shell — dropbear on a camera or a router —
  never answers the request to start SFTP, and the plugin waited for that
  answer with no time limit, so the connection hung until cancelled. It
  now gives up after fifteen seconds and suggests turning on "Use SCP for
  everything (no SFTP)", which is what such a host needs.

- **On shell-only servers, names with non-Latin letters are written in
  UTF-8.** With "Use SCP for everything" on, the plugin never worked out
  the server's encoding and fell back to the Windows codepage, so a file
  whose name holds letters outside Latin arrived under a name nothing on
  the server could read — present, yet invisible in the panel and blank
  in a terminal.
  The encoding is now detected as it is for SFTP, and a system with no
  locale at all — busybox on a camera or a router — is taken to be UTF-8.
  A session saved with an explicit encoding keeps it; switch it to
  Auto-detect to have it checked.

- **A file that is not there no longer reads as scp missing.** With "Use
  SCP for data transfers" on, asking for a file the server does not have
  — which `Shift+F4` does for a new name, before the editor opens — showed
  "Cannot execute SCP… make sure SCP is installed", although scp had only
  said there was no such file. The plugin now checks over SFTP and leaves
  a status line instead; the dialog stays for scp really refusing.

- **Uploading with "Use SCP for data transfers" works.** Opening the
  upload channel asks the server to start scp, which on the plugin's
  non-blocking connection first answers "not ready yet"; that answer was
  taken for a refusal, so nearly every upload failed with nothing in the
  log to say why. It is now asked again until the channel opens, as
  downloads always did.

- **SCP and shell transfers check that they really finished.** With
  "Use SCP for data transfers" on, a download the server cut short or
  padded after a read error, and an upload it could not finish writing —
  a full disk, a quota — both passed for complete: the status scp sends
  at the end was never read. Downloads through the shell likewise took
  whatever arrived for the whole file. Both now hold the result against
  what the server announced and fail when it falls short, and a shell
  upload whose local file stops reading partway fails as well.

- **A resumed upload no longer writes over a larger file on the
  server.** When the remote file was longer than the local one, or the
  server did not report its size, resuming started writing from the
  beginning without cutting the file, so the old tail stayed behind and
  the upload reported success. It now fails instead. An upload whose
  local file stops reading partway — a network drive dropping out, say —
  also fails now, rather than passing for complete with a short copy on
  the server.

- **Servers without SFTP work outside the login directory.** On a host
  that offers only a shell — dropbear on a camera or a router, say —
  every operation was asked for relative to wherever the login left the
  shell: listing, creating a folder, deleting, and both directions of
  file transfer. The panel showed the home directory in place of `/`,
  nothing outside it could be reached, and uploads landed in the wrong
  place or nowhere. Paths are now sent as they are. An account confined
  to its own directory, which only understands paths relative to it, is
  not served yet: retrying a refused path relative to the login
  directory was tried and dropped, because it could aim a deletion at a
  file nobody meant.

- **Shell transfer mode works.** Such a server echoes back every command
  it is sent, and the plugin mistook a command too long for one terminal
  line for the end of the output — so a transfer read nothing and
  reported an empty file. Uploads could not work at all this way, since
  they carry the file's data inside the command. The echo is now switched
  off, and the terminal asked for is wide enough that nothing wraps.

- **Renaming and moving on such a server work.** The command was built
  from the Windows form of the path, backslashes and all, which a shell
  reads as a name no file has — and whatever the shell then answered was
  taken as success, so nothing moved and nothing complained.

- **Downloading from such a server works at all.** The plugin waited for
  an acknowledgement that `scp` never sends when it is the one supplying
  the file, and mistook the first byte of the file's header for a broken
  protocol. Every download failed with "SCP Protocol Error".

- **A failed listing or deletion on such a server no longer passes for
  success.** A directory that could not be read looked exactly like an
  empty one, and a file that could not be deleted was reported as
  deleted — in both cases the answer the shell gave was thrown away
  before anyone looked at it.

- **Copying files from one server to another works.** With a different
  session open in each panel, copying between them failed immediately
  with "Error downloading file!" — nothing was transferred and nothing
  was even attempted. No single SFTP operation can join two servers, and
  Total Commander does not step in for a plugin here, so the plugin now
  carries the file itself: down from one session and up to the other,
  with one progress bar across both halves. Copy, move, several files at
  once and whole folders all work, in both directions. LAN Pair sessions
  are not part of this and refuse. Two sessions that point at the same
  account on the same server refuse to copy a file onto its own path,
  which would cut it short — and, on a move, delete it. Broken since the
  first release of the original plugin.

- **The jump-host list says what its first entry means.** It read
  "(none)", which looks like "no jump host" — while it actually meant
  "use the settings typed into Jump...". It now reads "(manual)", and the
  help describes the choice between those settings and a saved session
  for the first time. The list is also disabled in PHP and LAN Pair
  modes, like the controls beside it: picking a session there used to
  switch the jump host on, and the Jump... button with it, in a mode that
  never uses one.

- **The jump-host dialog shows where its settings come from.** When a
  session supplies the jump host, the dialog used to be unreachable —
  the button simply went grey — while anything typed into it on an
  earlier visit was quietly ignored at connect time. That is what made
  an agent problem there so hard to place. The button now opens, the
  fields show the referenced session's host, user and key files, and a
  line at the top names the session they belong to. They cannot be
  edited, and pressing OK leaves this session's own jump settings alone.
  Its duplicate "use jump host" checkbox is gone; the one on the main
  dialog was always the one that counted.

- **A session copied to another machine takes its proxy along.** Copying
  a session out of the plugin writes an INI file; until now that file
  named the proxy by its position in your list, so the session landed
  elsewhere pointing at a different proxy, or at none — connecting
  straight to the host. The proxy is now described in the file, and on
  the way back an identical one already present is reused instead of
  being duplicated. Passwords still stay behind, on both the session and
  the proxy, and are asked for on the first connection.

- **Proxies have a folder of their own.** `[Proxies]` sits in the plugin
  root next to `[Imports]`: one row per proxy, `F7` to add, `Enter` to
  edit, `F8` to delete. A proxy still used by a session is not deleted —
  the sessions using it are named. Deleting a proxy no longer renumbers
  the others, so no session quietly ends up on a different proxy than
  the one it was given, and the connection dialog keeps just the list.

- **The help now says which way of disconnecting actually works.** Close
  a session from inside it, or press F8 on its row in `[Active
  Sessions]`. The toolbar button pressed from the plugin root or a magic
  folder leaves the connection open — Total Commander never tells the
  plugin about that click, so nothing can act on it.

- **The LAN Pair box on the connection dialog is translated.** It kept
  its English caption in every language, because it was the one group
  box missing from the table that drives runtime translation — the mode
  switch shows it in place of the file-rights box, so the dialog looked
  translated in three transfer modes and half-translated in the fourth.

- **A session whose jump host cannot be resolved says so once, not on
  every reconnect.** When the bastion is missing — a deleted reference,
  or the checkbox left on with nothing filled in — the plugin refuses to
  connect rather than going straight to the target. The refusal is right;
  raising a dialog for it on each of the reconnects that run mid-transfer
  was not. It now appears once per connection and goes to the status line
  after that.

- **The interface language is taken from the language file's name, not
  from the path leading to it.** Total Commander's `LanguageIni` may
  hold a full path, and the whole string was searched for a language
  code — so a folder in that path could decide the language before the
  file name was reached, and a `.lng` sitting under a directory called
  `Ita` came out Italian whatever it was named. Spotted in the
  numbereleven-a fork.

- **LAN Pair no longer accumulates a thread per client for the life of
  the session.** The accept loop meant to drop finished worker threads
  but tested them with `joinable()`, which stays true until a thread is
  joined — so nothing was ever dropped and every connection left one
  behind until disconnect. Spotted in the numbereleven-a fork.

- **A batch TAR download can no longer come out truncated.** The
  server-side packer ignored what `fwrite` reported and counted the
  bytes it had *read* instead, so a short write left the archive
  missing data while the padding was computed for the full length —
  every following file in it shifted out of place. Writes now repeat
  until the buffer is gone. Re-upload `sftp.php` to pick this up.
  Spotted in the numbereleven-a fork.

### Internal

- libssh2 stays on its 1.11.1 tag, with Debian's security backports
  applied at build time from `thirdparty/patches/libssh2-1.11.1/`. The
  patches are bound to that tag: a submodule on any other tag is refused,
  and a new tag gets none until someone decides it needs them.

- OpenSSL updated to 3.5.9. Its fixes since 3.5.7 sit mostly in QUIC,
  DTLS, CMS and CRL handling, which SSH does not reach; taken to stay
  current rather than for a known exposure.

- Drawing an `[Imports]` folder no longer copies the whole cached
  session list once per row; the cache answers whether a row is a
  session directly. On a source holding a few hundred sessions that was
  hundreds of thousands of string allocations per repaint.

## 10.0.2.0 — 2026-08-19

### Features

- **The old Import... button is gone; importing lives in `[Imports]`.**
  The button in the connection dialog, the checkbox picker it opened
  and the whole flow behind it have been removed now that the
  `[Imports]` folder covers all five sources. Everything the button
  did is available there: `Enter` on a session connects using the
  source program's settings, `F5` copies it into your own session
  list, and `Ctrl+A` followed by `F5` takes a whole source at once.
  The freed space went back into the dialog's bottom row — `OK` and
  `Help` had been squeezed narrow to fit the button and were tight
  for the longer translations.

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

### Features from the beta cycle

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

- **`[Imports]\[KiTTY]` — KiTTY sessions as live virtual entries.**
  Same magic-folder UX. KiTTY is portable-first and has no canonical
  install path; the plugin probes three common locations in order
  (`%APPDATA%\KiTTY\Sessions\`, `%LOCALAPPDATA%\KiTTY\Sessions\`,
  `%USERPROFILE%\KiTTY\Sessions\`) and, as a last resort, resolves
  the KiTTY exe via the `HKCR\.kitty` file association registered
  by the KiTTY installer. If none match, the folder still appears
  once you add a portable directory through
  `[Add custom location...]` — pick either the `Sessions\` folder
  itself or the KiTTY install root (the adapter auto-descends when
  a `Sessions\` sibling of `kitty.exe` is present). Field mapping
  follows PuTTY (`HostName`, `PortNumber`, `UserName`,
  `PublicKeyFile`, `AgentFwd` / `AuthAgent`, `LineCodePage`,
  `EnterSendsCrLf`). Only `Protocol=ssh` entries appear;
  `Default%20Settings` template file is filtered out.
  **Passwords ARE imported** for KiTTY — deliberate exception to
  the "no password import" rule used for PuTTY / WinSCP / FileZilla,
  because autosave-password in KiTTY is an explicit user opt-in
  (not the default) and previous versions of this plugin's F11 flow
  always imported it. Decoded natively via the built-in
  `KittyDecrypt` (no external `kitty-decryptpassword.exe` helper
  needed) and re-wrapped with the plugin's own DPAPI obfuscation
  before it lands in the cache.

- **PPK ed25519 keys now work end-to-end.** Previously any imported
  or user-configured session pointing at an ed25519 `.ppk` failed
  auth silently (`PpkConverter` reported `unsupported_algorithm`;
  `SftpAuth` aborted with "Public-key auth aborted due to local key
  file error"). The converter now parses ed25519 PPK v3 blobs and
  emits a proper OpenSSH key container (`-----BEGIN OPENSSH PRIVATE
  KEY-----` — the same file format `ssh-keygen -t ed25519` writes),
  which libssh2 consumes directly through OpenSSL. Fix
  applies plugin-wide, not just to Import-related paths: hand-
  configured sessions with `privkeyfile=<...>.ppk` benefit too.
  RSA / ECDSA PPKs are unchanged. Encrypted-ed25519 PPKs and the
  Ed448 curve (PuTTY 0.75+ can write it) are not covered yet — open
  an issue if you need either.

### Fixes

- **The help row in the plugin root is named in your language.** Four
  translations carried a translated name and eleven still showed
  `F7 - help.txt`; all fifteen now match the interface language.

- **The `F7 - help.txt` text follows the plugin's language.** It was
  read straight from the compiled English resource, so the translations
  shipped in the `.lng` files never reached it. The file is UTF-8 now,
  with a byte-order mark so viewers read non-Latin text correctly.

- **F3 on the Quick Connection row no longer reports a download error.**
  It had no handler, so Total Commander tried to fetch the row from the
  server and failed. Both pseudo rows in the plugin root now show the
  plugin help, which is what they stand for.

- **Alt+Enter on a session inside `[Imports]` explains itself instead of
  doing nothing.** Imported sessions belong to the source program and
  are not editable here, but the key press was silently ignored. It now
  says so and points at `F3`, which shows the settings, and `F5`, which
  copies the session into your own list.

- **SecureCRT sessions pick up their key file the way the other sources
  do.** The path was taken from `Identity Filename V2` verbatim, so a
  `%USERPROFILE%`-style path stayed unexpanded and a `.pub` file landed
  in the private-key field. It now goes through the same expansion and
  public/private routing as PuTTY, WinSCP, FileZilla and KiTTY.

- **A long imported key path no longer arrives with its variables
  unexpanded.** Expansion used a fixed buffer and, when the result did
  not fit, silently handed back the original `%VAR%` text — which then
  failed at connect time with nothing pointing at the cause.

- **The `Session:` field is now just the session's name.** It used to be a
  dropdown of every saved session, and picking one loaded that session
  into the dialog — a session manager inside the window for editing one
  particular session. It had stopped working some releases ago, and while
  it worked it was a way to lose settings: choosing another session meant
  editing it under the name the dialog had opened with, so `OK` either
  refused with "session already exists" or saved one session's jump host,
  PHP, LAN-pair and encoding settings over another's. Sessions are chosen
  in the panel; the field names the session, and typing a different name
  renames it.

- **Saving a session under a name that already exists warns instead of
  replacing it.** Creating a session with a name already in use quietly
  overwrote that session from the connection dialog, and did nothing at
  all — no message, no session — when the name was typed at `F7`.
  Renaming onto a taken name already warned; all three paths now agree.

- **A passphrase you type to unlock a key is not offered to the server as
  a password.** A passphrase entered for a `.ppk` key was kept as the
  account password, so when key authentication then failed, the fallback
  sent that passphrase to the server as a login attempt. It now stays with
  the key. A password field holding a single unquoted value is still tried
  as both, since nothing says which it is — use the two-value form below
  to state it.

- **A password and a key passphrase stored together are read correctly.**
  The `"password","passphrase"` form was understood differently depending
  on which authentication method ran — one path used the second value as
  the account password, another as the passphrase, and the `.ppk` path
  ignored the split entirely and tried the whole field as a passphrase.
  The second value also came back with a stray trailing quote, so a
  passphrase stored this way never matched. One reading now applies
  everywhere: the first value is the account password, the second the key
  passphrase. This is also documented in the help file for the first
  time, and it now works for jump hosts as well. If you had relied on the
  previous order, swap the two values.

- **Changing a session's jump host no longer warns that the host key
  changed.** The fingerprint of the previous jump host stayed with the
  session, so pointing it at a different machine made the next connect
  compare the new host against the old one's key and report it as a
  change. Repointing the jump host now clears the stored fingerprint, and
  the machine is treated as first seen. A jump host taken from another
  saved session also no longer leaves its fingerprint behind in the
  session that referenced it.

- **Pageant authentication to a jump host works now.** If an SSH agent
  key was the only credential for the jump host, connecting failed
  immediately — the plugin never actually offered the key to the server.
  A saved key file or password for the jump host masked this, because
  the connection then succeeded through those instead. Reported and
  fixed by bukephalos (PR #2).

- **The jump-host session dropdown showed garbled text in translated
  builds, and its "(none)" entry did not work.** The list was filled
  through the ANSI window messages while the translations themselves
  are UTF-8, so any non-Latin caption came out as mojibake. The same
  mismatch broke the read-back: selecting the placeholder entry was
  interpreted as choosing a session literally named "(none)", so the
  plugin went looking for a jump host by that name instead of
  understanding that no jump host was wanted. Affected every language
  whose translation of "(none)" is not plain ASCII — Russian,
  Ukrainian, Japanese, Chinese and others.

- **Everything in the connection dialog is translated now.** The
  `Jump...` button had no string ID at all and stayed English in all
  15 languages. Twelve further strings — the jump-session dropdown
  entries, two jump-host error messages and the seven messages shown
  when a session INI is dropped onto the plugin — existed only in
  English. All are translated in every shipped language.

- **The jump-host row no longer overlaps itself in translated builds.**
  The row holds four controls — label, checkbox, session dropdown and
  button — but the code that arranges it only knew about three, and
  positioned the button directly after the checkbox text as if the
  dropdown were not there. English happened to land close enough to the
  designed position that it looked correct; any other caption length
  broke the row, either by stretching the checkbox across the dropdown
  or by pulling the button on top of it. The button is now anchored to
  the right edge and the dropdown gets the space between it and the
  checkbox. The Russian and Ukrainian checkbox captions were also
  shortened to just "Использовать" / "Використовувати", since the label
  immediately to their left already says which host is meant.

- **Unsupported Total Commander languages fall back to English.**
  Switching TC to a language the plugin ships no translation for left
  the plugin showing whichever language was selected before the
  switch, instead of reverting to English. Noticed with a Swedish TC,
  but it applied to every unsupported language. Note the plugin still
  reads the language once when it loads, so changing it in TC takes
  effect after restarting Total Commander.

- **The bundled help was months out of date.** The compiled `.chm` had
  not been regenerated since March because the build machine lacked
  the tool that produces it, so the build quietly shipped the old
  file. It now matches the current documentation — including the
  `[Imports]` folder, which had never been documented at all.

- **Imported sessions no longer lose encoding / line-ending
  auto-detection.** Every session materialised from an `[Imports]`
  folder was written with `utf8=0`, `unixlinebreaks=0` and
  `largefilesupport=0` pinned, even when the source program had no
  opinion on those settings. The plugin's own auto-detection was
  therefore permanently disabled for imported sessions — non-UTF-8
  servers showed mangled filenames, and the >2 GB capability probe
  never ran. The three fields now stay at their "auto" default
  unless the source program actually specifies a value.
- **WinSCP sessions with non-ASCII names now open.** A session named
  in Cyrillic, Greek, CJK, or anything else outside plain ASCII
  appeared in `[Imports]\[WinSCP]\` but silently failed on Enter —
  the plugin re-encoded the name using a narrower character set than
  WinSCP itself uses, so the lookup missed. Same fix covers names
  containing `/`, `?`, `*`, `"`, `<`, `>`, `|`, and a leading dot.
- **PuTTY and KiTTY sessions with punctuation in the name now open.**
  A session called e.g. `web01 (staging)` or `deploy@prod` was
  over-escaped on lookup and could not be found. The encoder now
  matches what PuTTY actually writes to disk — brackets, `@`, `+`,
  `=`, `;`, `#` and friends stay literal.
- **WinSCP workspace entries no longer show up as phantom sessions.**
  WinSCP stores saved window layouts under `Sessions\Workspaces\…`;
  these were listed as if they were real sessions and failed on
  Enter. Now filtered out, along with the unencoded
  `Default Settings` template row.
- **FileZilla: non-SFTP sites are hidden instead of failing on
  Enter.** FTP, FTPS, WebDAV and S3 entries from `sitemanager.xml`
  were listed in the folder and only rejected once you tried to open
  them. They are now filtered during the folder listing, matching how
  the WinSCP and KiTTY sources already behave.
- **Shift+F5 (same-panel copy) on a session or folder no longer
  throws you out of the plugin.** After a successful copy the
  plugin was posting `cm_RereadSource` unconditionally; for
  same-panel intra-plugin copy this races with Total Commander's
  own post-copy refresh and threw the user to the other panel's
  drive root. The extra refresh is now sent only for rename
  (`F6` / Move=TRUE), where our INI changes are invisible to TC
  and an explicit refresh is genuinely needed.

### Internal

- Decrypted passwords from FileZilla and KiTTY imports are overwritten
  in memory rather than left in freed buffers for a crash dump or the
  hibernation file to pick up — on the failure paths as well, where a
  half-decrypted buffer would otherwise survive. Best effort by nature:
  it covers the copy the adapter owns.

- Message boxes the plugin raises now go through one helper, which asks
  Total Commander to draw them (`RequestProcW`) and falls back to a bare
  `MessageBoxW` only where that callback is missing. Two of the three
  call sites were drawing their own.

- OpenSSL updated to 3.5.7, which carries seven CVE fixes including a
  high-severity use-after-free in `PKCS7_verify`. SSH does not reach
  the PKCS#7, CMS or QUIC code those mostly live in, but the ASN.1
  string-conversion overflow is on a path key and certificate parsing
  can take. libssh2 stays at 1.11.1 and argon2 at 20190702, both
  current.

- Built with the VS 2026 / MSVC v145 toolset, replacing VS 2022 and
  v143. OpenSSL, libssh2 and argon2 are rebuilt from source for every
  release, so they come from the new compiler too.

- Deleted the legacy import subsystem: `SessionImport.cpp` and its
  header, the session-picker dialog template, 41 resource IDs and 510
  lines of translation across the 15 shipped `.lng` files. Roughly
  2400 lines gone. Nothing shared was stranded — the folder picker,
  INI helpers, KiTTY decoder, DPAPI wrappers and PPK converter all
  keep independent callers in the adapter code.
- Session-import adapters share one set of primitives instead of
  carrying private copies: percent-encode / decode, registry string
  and DWORD readers, environment-variable expansion, key-file slot
  routing, and the cache hash all live in `ImportIoUtil` now. Removes
  roughly 200 lines of duplication across the five adapters and rules
  out the copies drifting apart.
- Removed `src/include/KittyDecryptDeploy.h` — an interface-only stub
  for deploying an external KiTTY password-decrypt helper. The
  decryptor is native C++ in the plugin, so no external binary was
  ever needed and nothing referenced the header.
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
