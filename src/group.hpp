#ifndef GROUP_HPP
#define GROUP_HPP 1

#include <memory>
#include <utility>
#include <vector>

#include "entry.hpp"

namespace pugi
{
    class xml_node;
}

namespace kdbx
{

class group_pvt;

class group
{
private:
    std::unique_ptr<group_pvt> _pvt;

public:
    group(const kdbx2& root, pugi::xml_node& node);
    group(group&&);
    ~group();

    //
    // Group Information
    //
    const char* uuid() const;
    const char* name() const;
    // TODO: Notes
    int icon_id() const;
    // TODO: Times
    bool is_expanded() const;
    // TODO: DefaultAutoTypeSequence
    const char* enable_auto_type() const;
    const char* enable_searching() const;
    const char* last_top_visible_entry() const;

    //
    // Entries
    //
    const std::vector<entry>& entries() const;
};

}

#endif
