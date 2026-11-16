#include "Utf8Escape.h"

namespace utf8_escape {

namespace {

bool IsCont(unsigned char c) noexcept
{
    return (c & 0xC0) == 0x80;
}

void AppendCodePoint(std::wstring& out, char32_t cp)
{
    if (cp < 0x10000) {
        out.push_back(static_cast<wchar_t>(cp));
    } else {
        cp -= 0x10000;
        out.push_back(static_cast<wchar_t>(0xD800 + (cp >> 10)));
        out.push_back(static_cast<wchar_t>(0xDC00 + (cp & 0x3FF)));
    }
}

void AppendUtf8(std::string& out, char32_t cp)
{
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

} // namespace

std::wstring Decode(std::string_view s)
{
    std::wstring out;
    out.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) {
            out.push_back(c);
            ++i;
            continue;
        }
        // The length and the range the second byte must fall in, as RFC 3629
        // has it: no overlong forms, no surrogates, nothing past U+10FFFF.
        size_t len = 0;
        unsigned char lo = 0x80, hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF)      { len = 2; }
        else if (c == 0xE0)              { len = 3; lo = 0xA0; }
        else if (c == 0xED)              { len = 3; hi = 0x9F; }
        else if (c >= 0xE1 && c <= 0xEF) { len = 3; }
        else if (c == 0xF0)              { len = 4; lo = 0x90; }
        else if (c >= 0xF1 && c <= 0xF3) { len = 4; }
        else if (c == 0xF4)              { len = 4; hi = 0x8F; }

        bool valid = len > 0 && i + len <= s.size();
        if (valid) {
            const unsigned char c1 = static_cast<unsigned char>(s[i + 1]);
            valid = c1 >= lo && c1 <= hi;
            for (size_t k = 2; valid && k < len; ++k)
                valid = IsCont(static_cast<unsigned char>(s[i + k]));
        }
        if (!valid) {
            out.push_back(static_cast<wchar_t>(0xDC00 + c));
            ++i;
            continue;
        }
        char32_t cp = c & (len == 2 ? 0x1F : len == 3 ? 0x0F : 0x07);
        for (size_t k = 1; k < len; ++k)
            cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
        AppendCodePoint(out, cp);
        i += len;
    }
    return out;
}

std::string Encode(std::wstring_view w)
{
    std::string out;
    out.reserve(w.size() * 3);
    for (size_t i = 0; i < w.size(); ++i) {
        const wchar_t u = w[i];
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < w.size() && w[i + 1] >= 0xDC00 && w[i + 1] <= 0xDFFF) {
            AppendUtf8(out, 0x10000 + ((static_cast<char32_t>(u) - 0xD800) << 10) + (w[i + 1] - 0xDC00));
            ++i;
        } else if (u >= 0xDC80 && u <= 0xDCFF) {
            out.push_back(static_cast<char>(u - 0xDC00));
        } else if (u >= 0xD800 && u <= 0xDFFF) {
            AppendUtf8(out, 0xFFFD);
        } else {
            AppendUtf8(out, u);
        }
    }
    return out;
}

} // namespace utf8_escape
