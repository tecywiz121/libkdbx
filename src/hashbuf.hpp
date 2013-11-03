#ifndef HASHBUF_HPP
#define HASHBUF_HPP 1
#include <cstdint>
#include <iostream>
#include <streambuf>
#include "cryptopp/secblock.h"
#include "cryptopp/sha.h"

namespace kdbx
{

class hashbuf : public std::streambuf
{
private:
    hashbuf(hashbuf&&);
    hashbuf(const hashbuf&);
    hashbuf& operator=(const hashbuf&);

    CryptoPP::SHA256 _hash;

    std::istream& _in;
    CryptoPP::SecByteBlock _buffer;
    bool _error = false;
    uint32_t _blk_idx;
    uint32_t _blk_len;
    CryptoPP::SecByteBlock _blk_hash;

    void update_ptr();
    void read_header();
    void read_body();
    void verify();

protected:
    int_type underflow() override;

public:
    explicit hashbuf(std::istream& in);
};

}

#endif
