#include <iostream>
#include "cryptopp/secblock.h"

namespace kdbx
{
template<typename T>
inline void read(std::istream& in, T& v)
{
    in.read(reinterpret_cast<char*>(&v), sizeof(v));
}

inline void read(std::istream& in, std::string& str, std::string::size_type size)
{
    // TODO: There is probably a better way to read in strings
    str.clear();
    str.reserve(size);

    for (std::string::size_type ii = 0; ii < size; ii++) {
        str.push_back(static_cast<char>(in.get()));
    }

    str.shrink_to_fit();
}

inline void read(std::istream& in, CryptoPP::SecByteBlock& buf,
            CryptoPP::SecByteBlock::size_type size)
{
    buf.CleanNew(size);
    in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(size));
}

inline void read_to_end(std::istream& in, std::string& out)
{
    char buffer[1024];
    while (in.good()) {
        in.read(buffer, 1024);
        std::string str(buffer, static_cast<std::string::size_type>(in.gcount()));
        out += str;
    }
}
}
