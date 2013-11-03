#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include "kdbx.hpp"
#include "io.hpp"
#include "hashbuf.hpp"

#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

#include "pugixml.hpp"

using pugi::xml_document;
using pugi::xml_node;
using pugi::xml_parse_result;

using std::string;
using std::stringstream;
using std::cout;
using std::endl;
using std::ifstream;
using std::istream;
using std::unordered_map;

using CryptoPP::SecByteBlock;
using CryptoPP::SHA256;
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::AES;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;

int main(int argc, char** argv)
{
    if (argc < 2) {
        cout << "Usage:" << endl;
        cout << "\t" << argv[0] << " <database>" << endl;
        return 1;
    }

    ifstream input(argv[1], std::ios::in | std::ios::binary);
    kdbx::kdbx2 db;
    db.push_key("test123");
    db.load(input);
#if 0
    cout << "Signature: " << db.signature1() << ", " << db.signature2() << endl;
    cout << "File Version: " << db.file_version() << endl;
    cout << "Comment: (" << db.comment().size() << ") " << db.comment() << endl;
    cout << "Cipher ID: (" << db.cipher_id().size() << ") " << db.cipher_id() << endl;
    cout << "Compression Flags: " << db.compression_flags() << endl;
    cout << "Transform Rounds: " << db.transform_rounds() << endl;
#endif
}

namespace kdbx
{

static bool starts_with(const string& str, const SecByteBlock& prefix)
{
    if (prefix.size() == 0) {
        return true;
    }

    if (str.size() < prefix.size()) {
        return false;
    }

    return !memcmp(str.data(), prefix.data(), prefix.size());
}

const unordered_map<string, void (kdbx2::*)(const char*)> kdbx2::_meta_setters = {
    {string("Generator"), &kdbx2::generator},
    {string("HeaderHash"), &kdbx2::header_hash},
    {string("DatabaseName"), &kdbx2::database_name},
    {string("DatabaseNameChanged"), &kdbx2::database_name_changed},
    {string("DatabaseDescription"), &kdbx2::database_description},
    {string("DatabaseDescriptionChanged"), &kdbx2::database_description_changed},
    {string("DefaultUserName"), &kdbx2::default_user_name},
    {string("DefaultUserNameChanged"), &kdbx2::default_user_name_changed},
    {string("MaintenanceHistoryDays"), &kdbx2::maintenance_history_days},
    {string("Color"), &kdbx2::color},
    {string("MasterKeyChanged"), &kdbx2::master_key_changed},
    {string("MasterKeyChangeRec"), &kdbx2::master_key_change_rec},
    {string("MasterKeyChangeForce"), &kdbx2::master_key_change_force},
    {string("RecycleBinEnabled"), &kdbx2::recycle_bin_enabled},
    {string("RecycleBinUUID"), &kdbx2::recycle_bin_uuid},
    {string("RecycleBinChanged"), &kdbx2::recycle_bin_changed},
    {string("EntryTemplatesGroup"), &kdbx2::entry_templates_group},
    {string("EntryTemplatesGroupChanged"), &kdbx2::entry_templates_group_changed},
    {string("HistoryMaxItems"), &kdbx2::history_max_items},
    {string("HistoryMaxSize"), &kdbx2::history_max_size},
    {string("LastSelectedGroup"), &kdbx2::last_selected_group},
    {string("LastTopVisibleGroup"), &kdbx2::last_top_visible_group},
};

void kdbx2::push_key(const string& key)
{
    SecByteBlock hash(SHA256::DIGESTSIZE);
    SHA256().CalculateDigest(hash.data(), reinterpret_cast<const byte*>(key.data()), key.size());
    _keys.Update(hash.data(), hash.size());
}

void kdbx2::clear_keys()
{
    _keys.Restart();
}

void kdbx2::load(istream& in)
{
    parse_signature(in);

    // Read the file version
    read(in, _file_version);

    parse_fields(in);
    parse_body(in);
}

void kdbx2::parse_signature(istream& in)
{
    read(in, _signature1);
    if (_signature1 != SIGNATURE[0]) {
        throw parse_error("invalid signature (0)");
    }

    read(in, _signature2);
    if (_signature2 != SIGNATURE[1]) {
        throw parse_error("invalid signature (1)");
    }
}

void kdbx2::parse_fields(istream& in)
{
    switch (file_version_major()) {
        case 0x01:
        case 0x02:
        case 0x03:
            parse_fields_v1(in);
            break;

        default:
            throw parse_error("unknown file version");
    }
}

void kdbx2::parse_body(istream& in)
{
    switch (file_version_major()) {
        case 0x01:
        case 0x02:
        case 0x03:
            parse_body_v1(in);
            break;

        default:
            throw parse_error("unknown file version");
    }
}

void kdbx2::parse_fields_v1(istream& in)
{
    /*
     * The format for each field is pretty much:
     *
     * struct {
     *    uint8_t field_id;
     *    uint16_t data_length;
     *    uint8_t data[];
     * };
     */

    uint8_t field_id;
    uint16_t length;

    while (true) {
        read(in, field_id);
        read(in, length);

        switch (field_id) {
            case FieldID::END_OF_HEADER:
                in.seekg(length, std::ios::cur); // Skip the end contents
                return;

            case FieldID::COMMENT:
                read(in, _comment, length);
                break;

            case FieldID::CIPHER_ID:
                read(in, _cipher_id, length);
                break;

            case FieldID::COMPRESSION_FLAGS:
                if (length != sizeof(_compression_flags)) {
                    throw parse_error("compression flags format unknown");
                }
                read(in, _compression_flags);
                break;

            case FieldID::MASTER_SEED:
                if (length != 32) {
                    throw parse_error("master seed unknown format");
                }
                read(in, _master_seed, length);
                break;

            case FieldID::TRANSFORM_SEED:
                if (length != 32) {
                    throw parse_error("transform seed unknown format");
                }
                read(in, _transform_seed, length);
                break;

            case FieldID::TRANSFORM_ROUNDS:
                if (length != sizeof(_transform_rounds)) {
                    throw parse_error("transform rounds unknown format");
                }
                read(in, _transform_rounds);
                break;

            case FieldID::ENCRYPTION_IV:
                read(in, _encryption_iv, length);
                break;

            case FieldID::PROTECTED_STREAM_KEY:
                read(in, _protected_stream_key, length);
                break;

            case FieldID::STREAM_START_BYTES:
                read(in, _stream_start_bytes, length);
                break;

            case FieldID::INNER_RANDOM_STREAM_ID:
                if (length != sizeof(_inner_random_stream_id)) {
                    throw parse_error("inner random stream id unknown format");
                }
                read(in, _inner_random_stream_id);
                break;

            default:
                throw parse_error("unknown header field");
        }
    }
}

void kdbx2::parse_body_v1(istream& in)
{
    // Build the master key
    SecByteBlock master_key(_keys.DigestSize());
    _keys.Final(master_key.data());

    // Encrypt the key _transform_rounds times
    ECB_Mode<AES>::Encryption key_transform(_transform_seed,
                                            _transform_seed.size());

    for (uint64_t ii = 0; ii < _transform_rounds; ii++) {
        key_transform.ProcessData(master_key.data(),
                                    master_key.data(),
                                    master_key.size());
    }

    // Hash the transformed key
    SHA256 hash;
    hash.Update(master_key.data(), master_key.size());
    hash.Final(master_key.data());

    // Combine the key with the master seed
    hash.Update(_master_seed.data(), _master_seed.size());
    hash.Update(master_key.data(), master_key.size());
    hash.Final(master_key.data());

    CBC_Mode<AES>::Decryption decryption(master_key,
                                            master_key.size(),
                                            _encryption_iv.data());

    string ciphertext;
    read_to_end(in, ciphertext);
    string plaintext;

    StringSource s(ciphertext, true,
        new StreamTransformationFilter(decryption,
            new StringSink(plaintext)
        ) // StreamTransformationFilter
    ); // StringSource

    if (!starts_with(plaintext, _stream_start_bytes)) {
        throw parse_error("incorrect password");
    }

    plaintext = plaintext.substr(_stream_start_bytes.size());

    // Read the plaintext using a validating stream buffer
    stringstream ss(plaintext);
    hashbuf buffer(ss);
    istream hash_stream(&buffer);

    xml_document doc;
    xml_parse_result result = doc.load(hash_stream);

    if (!result) {
        throw parse_error("XML error: " + string(result.description()));
    }


    xml_node kee = doc.child("KeePassFile");

    // Read the Meta tag
    xml_node meta = kee.child("Meta");

    for (xml_node child : meta) {
        try {
            (this->*_meta_setters.at(child.name()))(child.text().as_string());
        } catch (std::out_of_range& e) {
            // TODO: Print a warning or something
            std::cerr << "Unknown meta node: " << child.name() << endl;
        }
    }

    // Read the Root tag
    xml_node root = kee.child("Root");
    root.children();
}

}
