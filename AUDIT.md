# Phase 1 Import — pre-commit audit

Аудит по diff перед первым commit-ом магической папки `[Imports]`.
8 angles через subagents, cross-confirm по критичным пунктам.

Формат: **[ ]** — pending, **[x]** — done, **[-]** — deferred, отдельной задачей.

---

## 🔴 Регрессии (обязательно перед коммитом)

### 1. [ ] `g_inMultiOpTransfer` сузить до путей `\[Imports]\`
**Файлы:** `src/core/PluginEntryPoints.cpp:597`, `src/core/PluginEntryPointsFind.cpp:844`
**Проблема:** флаг ставится для любого `PUT_SINGLE`/`PUT_MULTI` глобально.
Обычный аплоад на сохранённую-но-ещё-не-подключённую сессию:
- `FsFindFirstW` short-circuits в `PATH_NOT_FOUND` без `SftpConnectToServer`
- `FsPutFileW` падает в session-import ветку с ошибкой «no server= key»
**Fix:** в `FsStatusInfo` при PUT-ветке проверять что `RemoteName` начинается с `\[Imports]\`; иначе не трогать флаг.

---

### 2. [ ] `FsPutFileW` — session-import ветка ловит валидные-но-неподключённые сессии
**Файл:** `src/core/PluginEntryPointsFile.cpp:1253-1376`
**Проблема:** `probeServer==nullptr` от `GetServerIdAndRelativePathFromPathW` не значит «не сессия» — значит «ещё не открыта в этом процессе». Даже после fix #1 остаётся риск.
**Fix:** входить в session-import ветку только когда `RemoteName` = плагин-корень (без сессии в пути), либо fallback-проверка через `GetPrivateProfileSectionA` до захода в парсинг.

---

### 3. [ ] `CopyIniSectionAcrossFiles` — очистка целевой секции
**Файл:** `src/core/PluginEntryPointsFile.cpp:80`
**Проблема:** `OverWrite=true` смешивает старые ключи с новыми. Пароли/proxy из старой сессии переживают перезапись. `CopyMoveServerInIniW` (ServerRegistry.cpp:206) первым делает `DeleteServerFromIniW`.
**Fix:** первым `WritePrivateProfileStringA(dstSection, nullptr, nullptr, dstIni)`, потом копировать.

---

### 4. [ ] Выключить логи в `global.h`
**Файл:** `src/include/global.h:80`
`LOG_ENABLED=0`, `LOG_TO_FILE=0`.

---

### 5. [ ] Комментарии «phase/step/previously/in the last test»
CLAUDE.md: «Комментарии должны отражать логику работы программы, а не историю изменения кода».

Локации:
- `src/core/PluginEntryPoints.cpp:593` — «Historically limited to RENMOV_MULTI; extended to PUT_SINGLE...»
- `src/core/PluginEntryPointsFile.cpp:402` — «no-op in Phase 1; step 8 populates...»
- `src/core/PluginEntryPointsFile.cpp:420` — «Phase 1 deliberately omits Password V2»
- `src/core/PluginEntryPointsFile.cpp:443` — «that is what popped the connection dialog in the last test»
- `src/core/PluginEntryPointsFile.cpp:1081` — «The previous behaviour opened the Edit Session dialog... this branch now exports raw INI»
- `src/core/PluginEntryPointsFind.cpp:453` — «once the ProfileSettings custom-paths API lands in step 8»

**Fix:** переписать на текущее поведение и «почему», без «раньше было / фаза N / step N».

---

## 🟡 Перед Phase 2 (мелкая полировка сейчас, чтоб не тащить дальше)

### 6. [ ] Заменить `u8ToW` лямбду на `unicode_util::narrow_to_wide`
**Файл:** `src/core/PluginEntryPointsFile.cpp:1267`
Утилита уже используется в этом же файле на строке 1407.

### 7. [ ] `ReplaceChannel` — писать секции по `channel`, а не `w.sourceOrigin`
**Файл:** `src/core/ImportCache.cpp:251`
**Проблема:** delete по `channel`, write по `w.sourceOrigin`. Если адаптер как-то нормализует путь между вызовами — orphaned секции на диске.
**Fix:** `SectionName(sourceId, channel, w.displayName)` для write, `ref.sourceOrigin = channel` для in-memory. Либо `assert(w.sourceOrigin == channel)`.

### 8. [ ] Разделитель custom-paths `;` → `|`
**Файл:** `src/core/ProfileSettings.cpp:250`
**Проблема:** `;` — легальный символ в имени папки Windows. Путь `C:\Sessions;Archive` разрежется на два несуществующих, `RemoveImportCustomPath` не найдёт исходный.
**Fix:** сменить разделитель на `|` (недопустим в путях). Учесть миграцию — читать оба.

---

## 🟢 Foundation для Phase 2-5 (адаптеры PuTTY / WinSCP / KiTTY / FileZilla)

### 9. [ ] `IsImportsPath` → возвращать enum
**Файл:** `src/core/PluginEntryPointsFind.cpp:750`
**Проблема:** 6 callsites сами комбинируют `sourceId.empty()` + `subPath.empty()`.
**Fix:** `enum PathKind { NotImports, Umbrella, UnknownSource, SourceRoot, SourceSubPath }`.

### 10. [ ] Валидация `SourceId` при регистрации адаптера
**Файл:** `src/core/ImportSourceRegistry.cpp:14`
**Проблема:** `ParseSectionName` требует lowercase-ASCII, no dots. Ничем не enforce'ится → Phase 2 автор напишет `"file.zilla"` → тихое повреждение cache на следующем перезапуске.
**Fix:** в конструкторе реестра assert/log при регистрации нарушителя.

### 11. [ ] Общие util: `WalkDirectory` + `IniSectionExists`
Дублирование с `src/core/SessionImport.cpp`:
- `WalkDir` в `SecureCrtAdapter.cpp:61` vs `FindPuttyRegInFolder` / `FindKittySessionsFolder` / `EnumerateKittyFolder` — 4 копии recursive walk уже, будет ×5+
- inline `GetPrivateProfileStringA(section,"server",...)` в `PluginEntryPointsFile.cpp:146` vs `IniSectionExists` в `SessionImport.cpp:194` (строже)
- `BrowseForCustomImportFolder` в `PluginEntryPointsFile.cpp:180` vs `BrowseForFolder` в `SessionImport.cpp:687`

**Fix:** вынести `WalkDirectory(root, predicate, callback)` и `IniSectionExists` в общий util (например `IoUtils.h/cpp` или расширить существующий).

### 12. [ ] Убрать misleading firewall-комментарии в `SecureCrtAdapter.h`
**Файл:** `src/include/SecureCrtAdapter.h:26`
Header заявляет «Firewall Name stored for later materialise-time proxy translation», но `FillConnectSettings` его вообще не читает.
**Fix:** либо реализовать (пробросить в `ExternalSessionEntry` и materialize), либо снять комментарий и записать в TODO как отдельную задачу.

---

## Follow-up после первичных 12 (foundation для Phase 2+)

- [x] **Reuse-3:** `BrowseForCustomImportFolder` → удалён; используется общий `sftp::BrowseForFolder` из `ImportIoUtil`.
- [x] **Alt-2 (было в TODO):** `CustomPathPickerKind { None, Folder, File }` в `IExternalSessionSource` + `CustomPathFileFilter()`. Dispatch в `FsExecuteFileW` и listing в `BuildImportsSourceListing`. `sftp::BrowseForFile` добавлен в util. SecureCrtAdapter override → `Folder`.
- [x] **Alt-5 (было в TODO):** `WriteSessionSection` переведён на sentinel-based policy, `password` теперь пишется когда адаптер его populated. Header comment документирует контракт и предупреждает про silent-drop.
- [x] **Refactor batch (#3-#8 из TODO):** `ImportCache::EraseChannelLocked`, `DedupBuckets`+`ClassifyRelativeEntry`+`EmitDedupBuckets` shared listing helpers, `CollectSessionsUnderFolder(prefix, iniW)`, ANSI MBToWC → `unicode_util::narrow_to_wide`, `TryExtractImportIcon`, `TryImportSessionFromUpload(std::optional<int>)`. Все механические extract-ы, без изменения поведения.

Остальное из «Phase 1 audit — remaining polish» (micro-efficiency + CoInitialize theoretical) — в TODO.md, оппортунистично.

---

## ⏸ Отложенные задачи (отдельными PR)

### F3/F4/F5 UX для обычных (не-Imports) сессий
**Локация:** `src/core/PluginEntryPointsFile.cpp:1081-1103`
**Регрессия:** F3/F4 на сохранённой сессии сейчас всегда экспортируют raw INI вместо `SftpConfigureServer` + `LoadServersFromIniW` + `FsDisconnect`. Edit round-trip потерян.
**План:** ветку `ExportSessionAsIniFile` применять только для путей `\[Imports]\`; для обычных сессий вернуть старое поведение.

### `F7 - help.txt` — обновить описание
Актуализировать под новый функционал: `[Imports]`, custom paths, materialize, Refresh, Add custom location.

---

_Готовим по порядку. По завершении каждого пункта — отметка `[x]` и коммит либо накопление под финальный commit._
