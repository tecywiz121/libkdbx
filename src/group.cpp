#include "group.hpp"

#include <cstring>
#include <vector>

#include "future.hpp"
#include "pugixml.hpp"

#include "entry.hpp"

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_parse_result;

using std::string;
using std::vector;

namespace kdbx
{

class group_pvt
{
public:
    const kdbx2& root;
    xml_node node;

    vector<entry> entries;

    group_pvt(const kdbx2& root, xml_node& node)
        : root(root), node(node) {}
};

group::group(const kdbx2& root, xml_node& node)
    : _pvt(std::make_unique<group_pvt>(root, node))
{
    // Find entries
    for (xml_node child : node) {
        if (0 == std::strcmp(child.name(), "Entry")) {
            _pvt->entries.emplace_back(_pvt->root, child);
        }
    }
}

group::group(group&& other)
    : _pvt(std::move(other._pvt))
{

}

group::~group()
{

}

const char* group::uuid() const
{
    return _pvt->node.first_element_by_path("UUID", '/').text().get();
}

const char* group::name() const
{
    return _pvt->node.first_element_by_path("Name", '/').text().get();
}

int group::icon_id() const
{
    return _pvt->node.first_element_by_path("IconId", '/').text().as_int();
}

bool group::is_expanded() const
{
    return _pvt->node.first_element_by_path("IsExpanded", '/').text().as_bool(false);
}

const vector<entry>& group::entries() const
{
    return _pvt->entries;
}
}
