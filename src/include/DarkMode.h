#pragma once
#include <windows.h>

// Dark colours for the plugin's dialogs, following Total Commander: when TC
// itself runs dark (its main window has the dark caption), every dialog the
// plugin opens is drawn dark as well; otherwise nothing changes.
namespace DarkMode {

// Whether the dialogs are to be drawn dark right now.
bool IsEnabled();

// Applies the dark look to a dialog and its controls when IsEnabled():
// caption, dark control themes, background and text colours, and its own
// drawing of check boxes, radio buttons and group boxes, whose text the
// system draws black whatever the colours. Call once from WM_INITDIALOG,
// after the controls exist.
void Apply(HWND hDlg);

// For tests: -1 follows Total Commander, 0 forces light, 1 forces dark.
void SetOverride(int mode);

} // namespace DarkMode
