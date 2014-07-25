#ifndef ENTRY_HPP
#define ENTRY_HPP 1

#include <memory>
#include <utility>

namespace pugi
{
    class xml_node;
}

namespace kdbx
{

class entry_pvt;
class kdbx2;

class entry
{
private:
    std::unique_ptr<entry_pvt> _pvt;

public:
    entry(const kdbx2& root, pugi::xml_node& node);
    entry(entry&&);
    ~entry();

    const char* uuid() const;
    // TODO: All the other fields

    const char* get_string(const std::string& key) const;
};

}

#endif
