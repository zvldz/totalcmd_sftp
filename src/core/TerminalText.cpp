#include "TerminalText.h"

namespace terminal_text {

namespace {

constexpr char kEsc = '\x1B';
constexpr char kBel = '\x07';

// Index just past a string control sequence (OSC, DCS, SOS, PM, APC) whose
// body starts at `i`; ST is ESC '\', and OSC may also end with BEL.
size_t SkipControlString(std::string_view s, size_t i, bool belEnds)
{
    while (i < s.size()) {
        if (belEnds && s[i] == kBel)
            return i + 1;
        if (s[i] == kEsc && i + 1 < s.size() && s[i + 1] == '\\')
            return i + 2;
        ++i;
    }
    return s.size();
}

} // namespace

std::string StripControls(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (c == kBel) {
            ++i;
            continue;
        }
        if (c != kEsc) {
            out.push_back(c);
            ++i;
            continue;
        }
        if (i + 1 >= s.size())
            break;
        const unsigned char next = static_cast<unsigned char>(s[i + 1]);
        if (next == '[') {
            // CSI: parameter bytes 0x30-0x3F, intermediates 0x20-0x2F, final 0x40-0x7E.
            size_t j = i + 2;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x30 && static_cast<unsigned char>(s[j]) <= 0x3F)
                ++j;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x20 && static_cast<unsigned char>(s[j]) <= 0x2F)
                ++j;
            i = (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x40 && static_cast<unsigned char>(s[j]) <= 0x7E) ? j + 1
                                                                                                                    : j;
        } else if (next == ']') {
            i = SkipControlString(s, i + 2, true);
        } else if (next == 'P' || next == 'X' || next == '^' || next == '_') {
            i = SkipControlString(s, i + 2, false);
        } else if (next >= 0x20 && next <= 0x2F) {
            // ESC, intermediates, final byte: ESC ( B, ESC # 8, ...
            size_t j = i + 1;
            while (j < s.size() && static_cast<unsigned char>(s[j]) >= 0x20 && static_cast<unsigned char>(s[j]) <= 0x2F)
                ++j;
            i = j < s.size() ? j + 1 : j;
        } else {
            // Two-byte forms: ESC =, ESC >, ESC 7, ESC M, ESC c, ...
            i += 2;
        }
    }
    return out;
}

std::string DecodeLsEscapedName(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) {
            out.push_back(s[i]);
            continue;
        }
        const char e = s[++i];
        if (e >= '0' && e <= '7' && i + 2 < s.size() &&
            s[i + 1] >= '0' && s[i + 1] <= '7' && s[i + 2] >= '0' && s[i + 2] <= '7') {
            out.push_back(static_cast<char>(((e - '0') << 6) | ((s[i + 1] - '0') << 3) | (s[i + 2] - '0')));
            i += 2;
            continue;
        }
        switch (e) {
            case 'n': out.push_back('\n'); break;
            case 't': out.push_back('\t'); break;
            case 'r': out.push_back('\r'); break;
            case 'a': out.push_back('\a'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'v': out.push_back('\v'); break;
            default:  out.push_back(e);    break;   // "\ ", "\\", ...
        }
    }
    return out;
}

} // namespace terminal_text
