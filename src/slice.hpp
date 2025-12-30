#pragma once

#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

namespace minilsm
{

struct Slice
{
        const char *data_;
        size_t size_;

        Slice() : data_(nullptr), size_(0) {}

        Slice(const char *data, size_t size) : data_(data), size_(size) {}

        Slice(const char *s) : data_(s), size_(std::strlen(s)) {}

        Slice(const std::string &s) : data_(s.data()), size_(s.size()) {}

        const char *data() const { return data_; }

        size_t size() const { return size_; }

        bool empty() const { return size_ == 0; }

        char operator[](size_t i) const { return data_[i]; }

        int compare(const Slice &other) const
        {
                size_t min_len = (size_ < other.size_) ? size_ : other.size_;
                int r = std::memcmp(data_, other.data_, min_len);
                if (r != 0)
                        return r;
                if (size_ < other.size_)
                        return -1;
                if (size_ > other.size_)
                        return 1;
                return 0;
        }

        bool operator==(const Slice &other) const
        {
                return size_ == other.size_ && std::memcmp(data_, other.data_, size_) == 0;
        }

        bool operator!=(const Slice &other) const { return !(*this == other); }

        bool operator<(const Slice &other) const { return compare(other) < 0; }

        std::string to_string() const { return std::string(data_, size_); }

        std::string_view to_string_view() const { return std::string_view(data_, size_); }
};

} // namespace minilsm
