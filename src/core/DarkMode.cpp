#include "DarkMode.h"

#include <commctrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <vssym32.h>

#include <algorithm>
#include <string>
#include <utility>

namespace DarkMode {

namespace {

int g_override = -1;

constexpr COLORREF kBackground = RGB(32, 32, 32);
constexpr COLORREF kControl = RGB(43, 43, 43);
constexpr COLORREF kText = RGB(240, 240, 240);
constexpr COLORREF kDisabledText = RGB(128, 128, 128);
constexpr COLORREF kFrame = RGB(80, 80, 80);
constexpr UINT_PTR kDialogSubclass = 0x5346'4450; // "SFDP"
constexpr UINT_PTR kButtonSubclass = 0x5346'4442; // "SFDB"

HBRUSH BackgroundBrush()
{
    static HBRUSH brush = CreateSolidBrush(kBackground);
    return brush;
}

HBRUSH ControlBrush()
{
    static HBRUSH brush = CreateSolidBrush(kControl);
    return brush;
}

// ---------------------------------------------------------------------------
// The undocumented uxtheme entry points that let a window take the dark
// variants of the system themes (Windows 10 1809 and later), by ordinal.
// ---------------------------------------------------------------------------
struct UxThemeDark {
    bool (WINAPI* allowDarkModeForWindow)(HWND, bool) = nullptr;            // #133
    int (WINAPI* setPreferredAppMode)(int) = nullptr;                       // #135
    void (WINAPI* refreshImmersiveColorPolicyState)() = nullptr;           // #104

    UxThemeDark()
    {
        HMODULE ux = LoadLibraryExW(L"uxtheme.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!ux)
            return;
        allowDarkModeForWindow = reinterpret_cast<decltype(allowDarkModeForWindow)>(GetProcAddress(ux, MAKEINTRESOURCEA(133)));
        setPreferredAppMode = reinterpret_cast<decltype(setPreferredAppMode)>(GetProcAddress(ux, MAKEINTRESOURCEA(135)));
        refreshImmersiveColorPolicyState =
            reinterpret_cast<decltype(refreshImmersiveColorPolicyState)>(GetProcAddress(ux, MAKEINTRESOURCEA(104)));
    }
};

const UxThemeDark& Ux()
{
    static const UxThemeDark ux;
    return ux;
}

bool IsClass(HWND hwnd, const wchar_t* name)
{
    wchar_t cls[32] = {};
    GetClassNameW(hwnd, cls, 32);
    return _wcsicmp(cls, name) == 0;
}

// Total Commander's main window: the dialog's top-level owner when it has
// one, otherwise the first window of TC's class in this process.
HWND TotalCommanderWindow()
{
    if (HWND active = GetActiveWindow()) {
        HWND root = GetAncestor(active, GA_ROOTOWNER);
        if (root && IsClass(root, L"TTOTAL_CMD"))
            return root;
    }
    std::pair<DWORD, HWND> search{GetCurrentProcessId(), nullptr};
    EnumWindows([](HWND h, LPARAM lp) -> BOOL {
        auto* s = reinterpret_cast<std::pair<DWORD, HWND>*>(lp);
        DWORD owner = 0;
        GetWindowThreadProcessId(h, &owner);
        if (owner == s->first && IsClass(h, L"TTOTAL_CMD")) {
            s->second = h;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&search));
    return search.second;
}

// ---------------------------------------------------------------------------
// Check boxes, radio buttons and group boxes
// ---------------------------------------------------------------------------
std::wstring TextOf(HWND hwnd)
{
    const int len = GetWindowTextLengthW(hwnd);
    std::wstring s(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(hwnd, s.data(), len + 1);
    s.resize(static_cast<size_t>(len));
    return s;
}

UINT TextFlags(HWND hwnd)
{
    // Mnemonic underlines only once the keyboard has been used, as the
    // system draws them.
    const LRESULT ui = SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0);
    return (ui & UISF_HIDEACCEL) ? DT_HIDEPREFIX : 0;
}

void PaintCheck(HWND hwnd, HDC dc, const RECT& rc, LONG type)
{
    const bool radio = type == BS_RADIOBUTTON || type == BS_AUTORADIOBUTTON;
    const bool enabled = IsWindowEnabled(hwnd) != FALSE;
    const LRESULT check = SendMessageW(hwnd, BM_GETCHECK, 0, 0);
    const LRESULT state = SendMessageW(hwnd, BM_GETSTATE, 0, 0);
    const bool pressed = (state & BST_PUSHED) != 0;
    const bool hot = (state & BST_HOT) != 0;

    int part = radio ? BP_RADIOBUTTON : BP_CHECKBOX;
    int partState;
    if (radio) {
        const int base = check == BST_CHECKED ? RBS_CHECKEDNORMAL : RBS_UNCHECKEDNORMAL;
        partState = base + (!enabled ? 3 : pressed ? 2 : hot ? 1 : 0);
    } else {
        const int base = check == BST_CHECKED ? CBS_CHECKEDNORMAL
                       : check == BST_INDETERMINATE ? CBS_MIXEDNORMAL : CBS_UNCHECKEDNORMAL;
        partState = base + (!enabled ? 3 : pressed ? 2 : hot ? 1 : 0);
    }

    SIZE glyph{13, 13};
    HTHEME theme = OpenThemeData(hwnd, L"Button");
    if (theme)
        GetThemePartSize(theme, dc, part, partState, nullptr, TS_DRAW, &glyph);
    RECT box{rc.left, rc.top + (rc.bottom - rc.top - glyph.cy) / 2, rc.left + glyph.cx, 0};
    box.bottom = box.top + glyph.cy;

    HFONT font = reinterpret_cast<HFONT>(SendMessageW(hwnd, WM_GETFONT, 0, 0));
    HGDIOBJ oldFont = font ? SelectObject(dc, font) : nullptr;
    TEXTMETRICW tm{};
    GetTextMetricsW(dc, &tm);

    // Only the band the glyph and the text take is cleared: after rounding a
    // control may reach a pixel into its neighbour, such as the bottom line
    // of a group box above it.
    const int band = (std::max)(static_cast<int>(glyph.cy), static_cast<int>(tm.tmHeight)) + 2;
    const int bandTop = rc.top + (rc.bottom - rc.top - band) / 2;
    RECT clear{rc.left, (std::max)(static_cast<int>(rc.top), bandTop), rc.right,
               (std::min)(static_cast<int>(rc.bottom), bandTop + band)};
    FillRect(dc, &clear, BackgroundBrush());
    if (theme) {
        DrawThemeBackground(theme, dc, part, partState, &box, nullptr);
        CloseThemeData(theme);
    } else {
        DrawFrameControl(dc, &box, DFC_BUTTON,
                         (radio ? DFCS_BUTTONRADIO : DFCS_BUTTONCHECK) | (check == BST_CHECKED ? DFCS_CHECKED : 0));
    }

    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, enabled ? kText : kDisabledText);
    // The system leaves a few pixels between glyph and text.
    RECT text{box.right + MulDiv(glyph.cx, 1, 3), rc.top, rc.right, rc.bottom};
    const std::wstring s = TextOf(hwnd);
    DrawTextW(dc, s.c_str(), static_cast<int>(s.size()), &text, DT_SINGLELINE | DT_VCENTER | TextFlags(hwnd));
    if (GetFocus() == hwnd && !(SendMessageW(hwnd, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS)) {
        RECT focus = text;
        DrawTextW(dc, s.c_str(), static_cast<int>(s.size()), &focus, DT_SINGLELINE | DT_CALCRECT | TextFlags(hwnd));
        OffsetRect(&focus, 0, (text.bottom - text.top - (focus.bottom - focus.top)) / 2);
        InflateRect(&focus, 1, 1);
        DrawFocusRect(dc, &focus);
    }
    if (oldFont)
        SelectObject(dc, oldFont);
}

void PaintGroupBox(HWND hwnd, HDC dc, const RECT& rc)
{
    HFONT font = reinterpret_cast<HFONT>(SendMessageW(hwnd, WM_GETFONT, 0, 0));
    HGDIOBJ oldFont = font ? SelectObject(dc, font) : nullptr;
    const std::wstring s = TextOf(hwnd);
    RECT textSize{0, 0, 0, 0};
    DrawTextW(dc, s.empty() ? L" " : s.c_str(), s.empty() ? 1 : static_cast<int>(s.size()), &textSize,
              DT_SINGLELINE | DT_CALCRECT);
    const int textH = textSize.bottom - textSize.top;

    // The frame starts half a text line down, where the caption sits on it.
    RECT frame{rc.left, rc.top + textH / 2, rc.right, rc.bottom};
    HPEN pen = CreatePen(PS_SOLID, 1, kFrame);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    Rectangle(dc, frame.left, frame.top, frame.right, frame.bottom);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);

    if (!s.empty()) {
        const int indent = MulDiv(textH, 1, 2);
        RECT text{rc.left + indent, rc.top, rc.left + indent + (textSize.right - textSize.left) + 4, rc.top + textH};
        FillRect(dc, &text, BackgroundBrush());
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, IsWindowEnabled(hwnd) ? kText : kDisabledText);
        text.left += 2;
        DrawTextW(dc, s.c_str(), static_cast<int>(s.size()), &text, DT_SINGLELINE | TextFlags(hwnd));
    }
    if (oldFont)
        SelectObject(dc, oldFont);
}

LRESULT CALLBACK ButtonProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR type)
{
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc{};
        GetClientRect(hwnd, &rc);
        // Drawn off screen, so a repaint does not flicker.
        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HGDIOBJ oldBmp = SelectObject(mem, bmp);
        // What is under the control stays where it does not draw: the inside
        // of a group box, and the edges of a check box.
        BitBlt(mem, 0, 0, rc.right, rc.bottom, dc, 0, 0, SRCCOPY);
        if (static_cast<LONG>(type) == BS_GROUPBOX)
            PaintGroupBox(hwnd, mem, rc);
        else
            PaintCheck(hwnd, mem, rc, static_cast<LONG>(type));
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_PRINTCLIENT: {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        if (static_cast<LONG>(type) == BS_GROUPBOX)
            PaintGroupBox(hwnd, reinterpret_cast<HDC>(wp), rc);
        else
            PaintCheck(hwnd, reinterpret_cast<HDC>(wp), rc, static_cast<LONG>(type));
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_ENABLE:
    case WM_SETTEXT:
    case BM_SETCHECK:
    case BM_SETSTATE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_UPDATEUISTATE:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_KEYUP:
    case WM_MOUSELEAVE: {
        // The default handlers draw the control directly; it is drawn again
        // in the dark colours right after.
        SendMessageW(hwnd, WM_SETREDRAW, FALSE, 0);
        const LRESULT r = DefSubclassProc(hwnd, msg, wp, lp);
        SendMessageW(hwnd, WM_SETREDRAW, TRUE, 0);
        InvalidateRect(hwnd, nullptr, FALSE);
        return r;
    }
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, ButtonProc, id);
        break;
    default:
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

// ---------------------------------------------------------------------------
// The dialog: background and the colours of its controls
// ---------------------------------------------------------------------------
LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR)
{
    switch (msg) {
    case WM_CTLCOLORDLG:
        return reinterpret_cast<LRESULT>(BackgroundBrush());
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wp);
        HWND ctrl = reinterpret_cast<HWND>(lp);
        // A read-only edit asks for static colours; it keeps the field look.
        const bool field = IsClass(ctrl, L"Edit");
        SetTextColor(dc, IsWindowEnabled(ctrl) ? kText : kDisabledText);
        SetBkColor(dc, field ? kControl : kBackground);
        return reinterpret_cast<LRESULT>(field ? ControlBrush() : BackgroundBrush());
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetTextColor(dc, kText);
        SetBkColor(dc, kControl);
        return reinterpret_cast<LRESULT>(ControlBrush());
    }
    case WM_CTLCOLORBTN:
        return reinterpret_cast<LRESULT>(BackgroundBrush());
    case WM_NCDESTROY:
        RemoveWindowSubclass(hwnd, DialogProc, id);
        break;
    default:
        break;
    }
    return DefSubclassProc(hwnd, msg, wp, lp);
}

void ThemeControl(HWND ctrl)
{
    if (Ux().allowDarkModeForWindow)
        Ux().allowDarkModeForWindow(ctrl, true);
    if (IsClass(ctrl, L"Button")) {
        const LONG type = GetWindowLongW(ctrl, GWL_STYLE) & BS_TYPEMASK;
        switch (type) {
        case BS_CHECKBOX: case BS_AUTOCHECKBOX: case BS_3STATE: case BS_AUTO3STATE:
        case BS_RADIOBUTTON: case BS_AUTORADIOBUTTON: case BS_GROUPBOX:
            SetWindowTheme(ctrl, L"DarkMode_Explorer", nullptr);
            SetWindowSubclass(ctrl, ButtonProc, kButtonSubclass, static_cast<DWORD_PTR>(type));
            break;
        default:
            SetWindowTheme(ctrl, L"DarkMode_Explorer", nullptr);
            break;
        }
    } else if (IsClass(ctrl, L"Edit")) {
        // A multi-line edit has scroll bars, which only the Explorer theme
        // draws dark; a single-line one takes the dark field border.
        const bool multiline = (GetWindowLongW(ctrl, GWL_STYLE) & ES_MULTILINE) != 0;
        SetWindowTheme(ctrl, multiline ? L"DarkMode_Explorer" : L"DarkMode_CFD", nullptr);
    } else if (IsClass(ctrl, L"ComboBox")) {
        SetWindowTheme(ctrl, L"DarkMode_CFD", nullptr);
    } else if (IsClass(ctrl, L"ScrollBar") || IsClass(ctrl, L"ListBox")) {
        SetWindowTheme(ctrl, L"DarkMode_Explorer", nullptr);
    }
    SendMessageW(ctrl, WM_THEMECHANGED, 0, 0);
}

} // namespace

void SetOverride(int mode)
{
    g_override = mode;
}

bool IsEnabled()
{
    if (g_override >= 0)
        return g_override == 1;
    HWND tc = TotalCommanderWindow();
    if (!tc)
        return false;
    BOOL dark = FALSE;
    // DWMWA_USE_IMMERSIVE_DARK_MODE: 20, and 19 on Windows 10 before 20H1.
    if (FAILED(DwmGetWindowAttribute(tc, 20, &dark, sizeof(dark))) &&
        FAILED(DwmGetWindowAttribute(tc, 19, &dark, sizeof(dark))))
        return false;
    return dark != FALSE;
}

void Apply(HWND hDlg)
{
    if (!hDlg || !IsEnabled())
        return;
    // ForceDark: the dark theme variants regardless of the Windows setting,
    // since Total Commander may be dark while Windows is light.
    if (Ux().setPreferredAppMode)
        Ux().setPreferredAppMode(2);
    if (Ux().refreshImmersiveColorPolicyState)
        Ux().refreshImmersiveColorPolicyState();
    if (Ux().allowDarkModeForWindow)
        Ux().allowDarkModeForWindow(hDlg, true);
    const BOOL dark = TRUE;
    if (FAILED(DwmSetWindowAttribute(hDlg, 20, &dark, sizeof(dark))))
        DwmSetWindowAttribute(hDlg, 19, &dark, sizeof(dark));

    SetWindowSubclass(hDlg, DialogProc, kDialogSubclass, 0);
    for (HWND c = GetWindow(hDlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
        ThemeControl(c);
    InvalidateRect(hDlg, nullptr, TRUE);
}

} // namespace DarkMode
