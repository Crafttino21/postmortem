// Bounds-checked little-endian reads over a CPER buffer.
//
// CLAUDE.md: "Bounds-check everything read from a CPER record. Offsets and
// lengths come from an untrusted file. Malformed input produces a diagnostic,
// never a crash." This class is how that rule is enforced - decoding code
// never indexes the buffer directly, so there is no place for an unchecked
// read to hide. Every accessor returns std::optional and a caller that ignores
// the emptiness gets a default value, not a wild read.

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace postmortem::cper {

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> data) : data_(data) {}

    [[nodiscard]] std::size_t size() const { return data_.size(); }
    [[nodiscard]] std::span<const std::uint8_t> all() const { return data_; }

    // True when [offset, offset + length) lies entirely inside the buffer.
    // The addition is checked, so a length near SIZE_MAX cannot wrap past it.
    [[nodiscard]] bool has(std::size_t offset, std::size_t length) const {
        if (offset > data_.size()) return false;
        return length <= data_.size() - offset;
    }

    [[nodiscard]] std::optional<std::uint8_t> u8(std::size_t offset) const {
        if (!has(offset, 1)) return std::nullopt;
        return data_[offset];
    }

    [[nodiscard]] std::optional<std::uint16_t> u16(std::size_t offset) const {
        return little_endian<std::uint16_t>(offset);
    }

    [[nodiscard]] std::optional<std::uint32_t> u32(std::size_t offset) const {
        return little_endian<std::uint32_t>(offset);
    }

    [[nodiscard]] std::optional<std::uint64_t> u64(std::size_t offset) const {
        return little_endian<std::uint64_t>(offset);
    }

    [[nodiscard]] std::optional<std::span<const std::uint8_t>> bytes(std::size_t offset,
                                                                     std::size_t length) const {
        if (!has(offset, length)) return std::nullopt;
        return data_.subspan(offset, length);
    }

    // A fixed-width text field. Stops at the first NUL, trims trailing spaces
    // and replaces anything unprintable with '.', because firmware fills these
    // with whatever it likes and the result goes straight to a terminal.
    [[nodiscard]] std::string text(std::size_t offset, std::size_t length) const {
        const auto raw = bytes(offset, length);
        if (!raw.has_value()) return {};

        std::string out;
        out.reserve(length);
        for (const std::uint8_t byte : *raw) {
            if (byte == 0) break;
            out += (byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.';
        }
        while (!out.empty() && out.back() == ' ') out.pop_back();
        return out;
    }

    // Convenience for the many fields that are simply absent on a short
    // structure; `fallback` is returned rather than failing the whole decode.
    template <class T>
    [[nodiscard]] T value_or(std::optional<T> value, T fallback) const {
        return value.has_value() ? *value : fallback;
    }

private:
    template <class T>
    [[nodiscard]] std::optional<T> little_endian(std::size_t offset) const {
        if (!has(offset, sizeof(T))) return std::nullopt;
        T value = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<T>(static_cast<T>(data_[offset + i]) << (8 * i));
        }
        return value;
    }

    std::span<const std::uint8_t> data_;
};

}  // namespace postmortem::cper
