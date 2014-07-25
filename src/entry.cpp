#include "entry.hpp"

#include <cstring>

#include "pugixml.hpp"
#include "future.hpp"

using std::string;

using pugi::xml_node;

namespace kdbx
{

class entry_pvt
{
public:
    const kdbx2& root;
    xml_node node;

    entry_pvt(const kdbx2& root, xml_node node)
        : root(root), node(node) {}
};

entry::entry(const kdbx2& root, xml_node& node)
    : _pvt(std::make_unique<entry_pvt>(root, node))
{

}

entry::entry(entry&& other)
    : _pvt(std::move(other._pvt))
{

}

entry::~entry()
{

}

const char* entry::uuid() const
{
    return _pvt->node.first_element_by_path("UUID", '/').text().get();
}

const char* entry::get_string(const string& key) const
{
    for (xml_node& outer : _pvt->node) {
        if (std::strcmp("String", outer.name()) == 0) {
            if (std::strcmp(key.c_str(), outer.child("Key").text().get()) == 0) {
                xml_node value = outer.child("Value");

                if (value.attribute("Protected").as_bool(false)) {
                    return "Protected";
                } else {
                    return value.text().get();
                }
            }
        }
    }

    return NULL;
}
}
