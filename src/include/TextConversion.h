#pragma once

#include <cstddef>
#include <vector>

// Line-ending conversion for text-mode transfers.
//
// Both converters are streaming state machines carrying one bit of state, so
// a stream fed in any chunking produces exactly the bytes the whole stream
// would. Output is appended to a separate buffer and never aliases the input,
// which is what makes the 2x worst-case growth of LF -> CRLF safe.
namespace text_conversion {

// Download direction: server LF -> Windows CRLF. Every LF not already preceded
// by CR gains one; CR and every other byte pass through unchanged.
class LfToCrLf {
public:
    // Appends the conversion of data[0, len) to out; returns the bytes appended
    // (between len and 2 * len).
    size_t Convert(const char* data, size_t len, std::vector<char>& out);
    void Reset() noexcept { lastWasCr_ = false; }

private:
    bool lastWasCr_ = false;
};

// Upload direction: Windows CRLF -> server LF. A CR immediately followed by LF
// is dropped; a CR anywhere else is data and is kept. A CR that ends a chunk is
// held back until the next chunk, or Finish(), shows what follows it.
class CrLfToLf {
public:
    size_t Convert(const char* data, size_t len, std::vector<char>& out);
    // Emits a held-back CR. Call exactly once, after the last chunk.
    size_t Finish(std::vector<char>& out);

    // Same state transitions as Convert/Finish, counting instead of writing.
    // Used to announce the exact converted size before an SCP upload starts.
    size_t Count(const char* data, size_t len);
    size_t FinishCount();

    void Reset() noexcept { pendingCr_ = false; }

private:
    template <typename Emit> size_t Run(const char* data, size_t len, Emit&& emit);

    bool pendingCr_ = false;
};

// A download in text mode: the first kWindow bytes are held until they show
// whether the file is text — a NUL among them makes it binary (UTF-16 text
// included), which line-break conversion would corrupt — and every transfer
// path decides on the same bytes, however its data arrives. Then text goes
// through LfToCrLf and binary data as it is.
class DownloadText {
public:
    static constexpr size_t kWindow = 64 * 1024;

    explicit DownloadText(bool textMode) noexcept : text_(textMode), deciding_(textMode) {}
    // Appends to `out` what can be written now; returns the bytes appended.
    size_t Feed(const char* data, size_t len, std::vector<char>& out);
    // Releases what is still held. Call once, after the last chunk.
    size_t Finish(std::vector<char>& out);
    // Still text mode (false once a NUL was seen).
    bool Text() const noexcept { return text_; }

private:
    size_t Release(std::vector<char>& out);

    bool text_;
    bool deciding_;
    std::vector<char> held_;
    LfToCrLf toCrLf_;
};

} // namespace text_conversion
