#include <algorithm>
#include "hashbuf.hpp"
#include "io.hpp"
#include "errors.hpp"

namespace kdbx
{

hashbuf::hashbuf(std::istream& in)
    : _in(in)
{
    update_ptr();
}

hashbuf::int_type hashbuf::underflow()
{
    if (gptr() < egptr()) {
        // Still have characters in the buffer
        return traits_type::to_int_type(*gptr());
    }

    read_header();
    read_body();

    if (_buffer.size() == 0) {
        return hashbuf::traits_type::eof();
    }

    verify();
    update_ptr();


    return hashbuf::traits_type::to_int_type(*gptr());
}

void hashbuf::read_header() {
    read(_in, _blk_idx);
    read(_in, _blk_hash, 32);
    read(_in, _blk_len);
}

void hashbuf::read_body() {
    read(_in, _buffer, _blk_len);
}

void hashbuf::verify() {
    if (!_hash.VerifyDigest(_blk_hash.data(), _buffer.data(), _buffer.size())) {
        throw parse_error("block signature invalid");
    }
}

void hashbuf::update_ptr()
{
    hashbuf::char_type* start = reinterpret_cast<char_type*>(_buffer.begin());
    hashbuf::char_type* end = reinterpret_cast<char_type*>(_buffer.end());

    setg(start, start, end);
}

}
