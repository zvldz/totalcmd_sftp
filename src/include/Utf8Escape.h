#pragma once

#include <string>
#include <string_view>

// Remote names are bytes. In a UTF-8 session most are valid UTF-8, but a
// name written by something else may hold bytes that are not; decoded the
// usual way they all become U+FFFD and the name can no longer be sent back.
// Here each such byte becomes a lone low surrogate U+DC80..U+DCFF, which no
// valid text contains, and turns back into the same byte on the way out, so
// every name survives the round trip unchanged.
namespace utf8_escape {

// UTF-8 bytes to UTF-16; a byte that is not part of a valid sequence becomes
// U+DC00 + byte.
std::wstring Decode(std::string_view bytes);

// The reverse: UTF-16 to UTF-8, with U+DC80..U+DCFF not paired with a high
// surrogate written as the byte it stands for. Any other lone surrogate is
// written as U+FFFD.
std::string Encode(std::wstring_view text);

} // namespace utf8_escape
