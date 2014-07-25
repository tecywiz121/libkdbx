#ifndef KDBX_HPP
#define KDBX_HPP 1

#include <string>
#include <cstdint>
#include <vector>
#include <memory>

#include "errors.hpp"
#include "group.hpp"

namespace kdbx
{

class kdbx2_pvt;

class kdbx2
{
private:
    std::unique_ptr<kdbx2_pvt> _pvt;

public:
    kdbx2();
    ~kdbx2();

    //
    // Header
    //
    uint32_t signature1() const;
    uint32_t signature2() const;
    uint32_t file_version() const;
    uint16_t file_version_minor() const;
    uint16_t file_version_major() const;
    const std::string& comment() const;
    const std::string& cipher_id() const;
    uint32_t compression_flags() const;
    uint64_t transform_rounds() const;
    uint32_t inner_random_stream_id() const;

    //
    // Meta
    //
    const char* generator() const;
    const char* header_hash() const;
    const char* database_name() const;
    const char* database_name_changed() const;
    const char* database_description() const;
    const char* database_description_changed() const;
    const char* default_user_name() const;
    const char* default_user_name_changed() const;
    const char* maintenance_history_days() const;
    const char* color() const;
    const char* master_key_changed() const;
    int master_key_change_rec() const;
    int master_key_change_force() const;
    bool recycle_bin_enabled() const;
    const char* recycle_bin_uuid() const;
    const char* recycle_bin_changed() const;
    const char* entry_templates_group() const;
    const char* entry_templates_group_changed() const;
    const char* history_max_items() const;
    const char* history_max_size() const;
    const char* last_selected_group() const;
    const char* last_top_visible_group() const;

    //
    // Groups
    //
    const std::vector<group>& groups() const;

    void push_key(const std::string& key);
    void clear_keys();
    void load(std::istream& in);
};


}

#endif
