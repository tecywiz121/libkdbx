#ifndef KDBX_HPP
#define KDBX_HPP 1

#include <string>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <unordered_map>

#include "cryptopp/secblock.h"
#include "cryptopp/sha.h"

#include "errors.hpp"

namespace kdbx
{

class kdbx2
{
private:
    //
    // Header
    //
    uint32_t _signature1;
    uint32_t _signature2;
    uint32_t _file_version;

    std::string _comment;
    std::string _cipher_id;
    uint32_t _compression_flags;
    CryptoPP::SecByteBlock _master_seed;
    CryptoPP::SecByteBlock _transform_seed;
    uint64_t _transform_rounds;
    CryptoPP::SecByteBlock _encryption_iv;
    CryptoPP::SecByteBlock _protected_stream_key;
    CryptoPP::SecByteBlock _stream_start_bytes;
    uint32_t _inner_random_stream_id;

    //
    // Meta
    //
    std::string _generator;
    std::string _header_hash;
    std::string _database_name;
    std::string _database_name_changed;
    std::string _database_description;
    std::string _database_description_changed;
    std::string _default_user_name;
    std::string _default_user_name_changed;
    std::string _maintenance_history_days;
    std::string _color;
    std::string _master_key_changed;
    int _master_key_change_rec;
    int _master_key_change_force;
    // TODO: Memory Protection
    bool _recycle_bin_enabled;
    std::string _recycle_bin_uuid;
    std::string _recycle_bin_changed;
    std::string _entry_templates_group;
    std::string _entry_templates_group_changed;
    std::string _history_max_items;
    std::string _history_max_size;
    std::string _last_selected_group;
    std::string _last_top_visible_group;
    // TODO: Binaries
    // TODO: Custom Data


    CryptoPP::SHA256 _keys;

    void parse_signature(std::istream& in);
    void parse_fields(std::istream& in);
    void parse_fields_v1(std::istream& in);

    void parse_body(std::istream& in);
    void parse_body_v1(std::istream& in);

    //
    // Meta
    //
    void generator(const char* txt) { _generator = txt; }
    void header_hash(const char* txt) { _header_hash = txt; }
    void database_name(const char* txt) { _database_name = txt; }
    void database_name_changed(const char* txt) { _database_name_changed = txt; }
    void database_description(const char* txt) { _database_description = txt; }
    void database_description_changed(const char* txt) { _database_description_changed = txt; }
    void default_user_name(const char* txt) { _default_user_name = txt; }
    void default_user_name_changed(const char* txt) { _default_user_name_changed = txt; }
    void maintenance_history_days(const char* txt) { _maintenance_history_days = txt; }
    void color(const char* txt) { _color = txt; }
    void master_key_changed(const char* txt) { _master_key_changed = txt; }
    void master_key_change_rec(const char* txt) { _master_key_change_rec = std::atoi(txt); }
    void master_key_change_force(const char* txt) { _master_key_change_force = std::atoi(txt); }
    void recycle_bin_enabled(const char* txt) { _recycle_bin_enabled = !std::strncmp("True", txt, 4); }
    void recycle_bin_uuid(const char* txt) { _recycle_bin_uuid = txt; }
    void recycle_bin_changed(const char* txt) { _recycle_bin_changed = txt; }
    void entry_templates_group(const char* txt) { _entry_templates_group = txt; }
    void entry_templates_group_changed(const char* txt) { _entry_templates_group_changed = txt; }
    void history_max_items(const char* txt) { _history_max_items = txt; }
    void history_max_size(const char* txt) { _history_max_size = txt; }
    void last_selected_group(const char* txt) { _last_selected_group = txt; }
    void last_top_visible_group(const char* txt) { _last_top_visible_group = txt; }
    static const std::unordered_map<std::string, void (kdbx2::*)(const char*)> _meta_setters;

public:
    enum FieldID
    {
        END_OF_HEADER = 0,
        COMMENT,
        CIPHER_ID,
        COMPRESSION_FLAGS,
        MASTER_SEED,
        TRANSFORM_SEED,
        TRANSFORM_ROUNDS,
        ENCRYPTION_IV,
        PROTECTED_STREAM_KEY,
        STREAM_START_BYTES,
        INNER_RANDOM_STREAM_ID,
    };

    const uint32_t SIGNATURE[2] = {0x9AA2D903, 0xB54BFB67};

    //
    // Header
    //
    uint32_t signature1() const { return _signature1; }
    uint32_t signature2() const { return _signature2; }
    uint32_t file_version() const { return _file_version; }
    uint16_t file_version_minor() const { return _file_version & 0xFFFF; }
    uint16_t file_version_major() const { return static_cast<uint16_t>(_file_version >> 16); }
    const std::string& comment() const { return _comment; }
    const std::string& cipher_id() const { return _cipher_id; }
    uint32_t compression_flags() const { return _compression_flags; }
    uint64_t transform_rounds() const { return _transform_rounds; }
    uint32_t inner_random_stream_id() const { return _inner_random_stream_id; }

    //
    // Meta
    //
    const std::string& generator() const { return _generator; }
    const std::string& header_hash() const { return _header_hash; }
    const std::string& database_name() const { return _database_name; }
    const std::string& database_name_changed() const { return _database_name_changed; }
    const std::string& database_description() const { return _database_description; }
    const std::string& database_description_changed() const { return _database_description_changed; }
    const std::string& default_user_name() const { return _default_user_name; }
    const std::string& default_user_name_changed() const { return _default_user_name_changed; }
    const std::string& maintenance_history_days() const { return _maintenance_history_days; }
    const std::string& color() const { return _color; }
    const std::string& master_key_changed() const { return _master_key_changed; }
    int master_key_change_rec() const { return _master_key_change_rec; }
    int master_key_change_force() const { return _master_key_change_force; }
    bool recycle_bin_enabled() const { return _recycle_bin_enabled; }
    const std::string& recycle_bin_uuid() const { return _recycle_bin_uuid; }
    const std::string& recycle_bin_changed() const { return _recycle_bin_changed; }
    const std::string& entry_templates_group() const { return _entry_templates_group; }
    const std::string& entry_templates_group_changed() const { return _entry_templates_group_changed; }
    const std::string& history_max_items() const { return _history_max_items; }
    const std::string& history_max_size() const { return _history_max_size; }
    const std::string& last_selected_group() const { return _last_selected_group; }
    const std::string& last_top_visible_group() const { return _last_top_visible_group; }

    void push_key(const std::string& key);
    void clear_keys();
    void load(std::istream& in);
};


}

#endif
