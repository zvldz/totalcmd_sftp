#pragma once

#include <windows.h>
#include <string>
#include "SftpClient.h"

INT_PTR WINAPI ProxyDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
INT_PTR WINAPI ConnectDlgProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam);
bool ShowConnectDialog(pConnectSettings ConnectSettings, LPCSTR DisplayName, LPCSTR inifilename);
void fillProxyCombobox(HWND hWnd, int defproxynr, LPCSTR iniFileName);

// Helpers implemented in SftpConnection.cpp and used by dialog module.
bool LoadProxySettingsFromNr(int proxynr, pConnectSettings ConnectResults, LPCSTR iniFileName);

// Proxy records, managed from the [Proxies] folder as well as from the
// connection dialog. A record is identified by its number, which never moves.
std::wstring DescribeProxyRecordW(int proxynr, LPCSTR iniFileName);
bool ShowProxyRecordDialog(int proxynr, LPCSTR iniFileName);
int  CreateProxyRecordDialog(LPCSTR iniFileName);
bool DeleteProxy(int proxynrtodelete, LPCSTR ServerToSkip, LPCSTR iniFileName,
                 LPSTR AppendToList, size_t maxlen);
bool LoadServerSettings(LPCSTR DisplayName, pConnectSettings ConnectResults, LPCSTR iniFileName);
void UpdateKeyControlsForPrivateKey(HWND hWnd);
void UpdateScpOnlyDependentControls(HWND hWnd);
bool UpdateLocalPhpAgentScriptWithPassword(LPCSTR plainPassword);
// The plugin's folder in UTF-8, without a trailing backslash.
bool GetPluginDirectoryU8(std::string& outDir);
// Stores `password` for `key` in `section`: in Total Commander's password
// store under `storeName` when `useStore`, otherwise encrypted in the INI.
void SavePasswordSetting(HWND hWnd, const char* section, const char* key,
                         const char* storeName, const std::string& password,
                         bool useStore, const char* iniFileName);
void OpenPluginHelp(HWND hWnd);
std::wstring GetPluginVersionW();

constexpr int kCodepageListCount = 24;
extern int codepagelist[kCodepageListCount];
