#include "TextConversion.h"
#include <algorithm>

namespace text_conversion {

size_t LfToCrLf::Convert(const char* data, size_t len, std::vector<char>& out)
{
    const size_t before = out.size();
    out.reserve(before + 2 * len);
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (c == '\n' && !lastWasCr_)
            out.push_back('\r');
        out.push_back(c);
        lastWasCr_ = (c == '\r');
    }
    return out.size() - before;
}

template <typename Emit>
size_t CrLfToLf::Run(const char* data, size_t len, Emit&& emit)
{
    size_t emitted = 0;
    for (size_t i = 0; i < len; ++i) {
        const char c = data[i];
        if (pendingCr_) {
            pendingCr_ = false;
            if (c != '\n') {
                emit('\r');
                ++emitted;
            }
        }
        if (c == '\r') {
            pendingCr_ = true;
            continue;
        }
        emit(c);
        ++emitted;
    }
    return emitted;
}

size_t CrLfToLf::Convert(const char* data, size_t len, std::vector<char>& out)
{
    out.reserve(out.size() + len);
    return Run(data, len, [&out](char c) { out.push_back(c); });
}

size_t CrLfToLf::Finish(std::vector<char>& out)
{
    if (!pendingCr_)
        return 0;
    pendingCr_ = false;
    out.push_back('\r');
    return 1;
}

size_t CrLfToLf::Count(const char* data, size_t len)
{
    return Run(data, len, [](char) {});
}

size_t CrLfToLf::FinishCount()
{
    const size_t held = pendingCr_ ? 1 : 0;
    pendingCr_ = false;
    return held;
}

size_t DownloadText::Release(std::vector<char>& out)
{
    deciding_ = false;
    size_t n = 0;
    if (text_) {
        n = toCrLf_.Convert(held_.data(), held_.size(), out);
    } else {
        out.insert(out.end(), held_.begin(), held_.end());
        n = held_.size();
    }
    held_.clear();
    held_.shrink_to_fit();
    return n;
}

size_t DownloadText::Feed(const char* data, size_t len, std::vector<char>& out)
{
    if (deciding_) {
        held_.insert(held_.end(), data, data + len);
        // Only the first kWindow bytes decide, however the chunks fall.
        const auto windowEnd = held_.begin() + static_cast<std::ptrdiff_t>((std::min)(held_.size(), kWindow));
        if (std::find(held_.begin(), windowEnd, '\0') != windowEnd)
            text_ = false;
        if (!text_ || held_.size() >= kWindow)
            return Release(out);
        return 0;
    }
    if (text_)
        return toCrLf_.Convert(data, len, out);
    out.insert(out.end(), data, data + len);
    return len;
}

size_t DownloadText::Finish(std::vector<char>& out)
{
    return deciding_ ? Release(out) : 0;
}

} // namespace text_conversion
