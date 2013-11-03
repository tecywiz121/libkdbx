#ifndef ERRORS_HPP
#define ERRORS_HPP 1

#include <stdexcept>

namespace kdbx
{

class parse_error : public std::runtime_error
{
public:
    explicit parse_error(const std::string& what_arg)
        : runtime_error(what_arg) {}
    explicit parse_error(const char* what_arg)
        : runtime_error(what_arg) {}
};

}

#endif
