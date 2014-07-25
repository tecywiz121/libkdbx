#include "kdbx.hpp"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>
#include <unordered_map>

#include "cryptopp/aes.h"
#include "cryptopp/ccm.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

#include "pugixml.hpp"

#include "future.hpp"

#include "io.hpp"
#include "hashbuf.hpp"

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
using std::vector;

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

    for (const kdbx::group& g : db.groups()) {
        cout << g.uuid() << endl;
        for (const kdbx::entry& e : g.entries()) {
            cout << "\t" << e.uuid() << " " << e.get_string("UserName") << endl;
        }
    }

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

class kdbx2_pvt
{
private:
    kdbx2& _pub;

public:
    kdbx2_pvt(kdbx2& pub) : _pub(pub) {}

    //
    // Header
    //
    const uint32_t SIGNATURE[2] = {0x9AA2D903, 0xB54BFB67};

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


    uint32_t signature1;
    uint32_t signature2;
    uint32_t file_version;

    std::string comment;
    std::string cipher_id;
    uint32_t compression_flags;
    CryptoPP::SecByteBlock master_seed;
    CryptoPP::SecByteBlock transform_seed;
    uint64_t transform_rounds;
    CryptoPP::SecByteBlock encryption_iv;
    CryptoPP::SecByteBlock protected_stream_key;
    CryptoPP::SecByteBlock stream_start_bytes;
    uint32_t inner_random_stream_id;


    CryptoPP::SHA256 keys;

    void parse_signature(std::istream& in);
    void parse_fields(std::istream& in);
    void parse_fields_v1(std::istream& in);

    void parse_body(std::istream& in);
    void parse_body_v1(std::istream& in);

    //
    // Groups
    //
    vector<group> groups;

    //
    // XML
    //
    xml_document document;
    xml_node meta;
};

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

kdbx2::kdbx2()
    : _pvt(std::make_unique<kdbx2_pvt>(*this))
{

}

kdbx2::~kdbx2()
{

}

void kdbx2::push_key(const string& key)
{
    SecByteBlock hash(SHA256::DIGESTSIZE);
    SHA256().CalculateDigest(hash.data(), reinterpret_cast<const byte*>(key.data()), key.size());
    _pvt->keys.Update(hash.data(), hash.size());
}

void kdbx2::clear_keys()
{
    _pvt->keys.Restart();
}

void kdbx2::load(istream& in)
{
    _pvt->parse_signature(in);

    // Read the file version
    read(in, _pvt->file_version);

    _pvt->parse_fields(in);
    _pvt->parse_body(in);
}

void kdbx2_pvt::parse_signature(istream& in)
{
    read(in, signature1);
    if (signature1 != SIGNATURE[0]) {
        throw parse_error("invalid signature (0)");
    }

    read(in, signature2);
    if (signature2 != SIGNATURE[1]) {
        throw parse_error("invalid signature (1)");
    }
}

void kdbx2_pvt::parse_fields(istream& in)
{
    switch (_pub.file_version_major()) {
        case 0x01:
        case 0x02:
        case 0x03:
            parse_fields_v1(in);
            break;

        default:
            throw parse_error("unknown file version");
    }
}

void kdbx2_pvt::parse_body(istream& in)
{
    switch (_pub.file_version_major()) {
        case 0x01:
        case 0x02:
        case 0x03:
            parse_body_v1(in);
            break;

        default:
            throw parse_error("unknown file version");
    }
}

void kdbx2_pvt::parse_fields_v1(istream& in)
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
                read(in, comment, length);
                break;

            case FieldID::CIPHER_ID:
                read(in, cipher_id, length);
                break;

            case FieldID::COMPRESSION_FLAGS:
                if (length != sizeof(compression_flags)) {
                    throw parse_error("compression flags format unknown");
                }
                read(in, compression_flags);
                break;

            case FieldID::MASTER_SEED:
                if (length != 32) {
                    throw parse_error("master seed unknown format");
                }
                read(in, master_seed, length);
                break;

            case FieldID::TRANSFORM_SEED:
                if (length != 32) {
                    throw parse_error("transform seed unknown format");
                }
                read(in, transform_seed, length);
                break;

            case FieldID::TRANSFORM_ROUNDS:
                if (length != sizeof(transform_rounds)) {
                    throw parse_error("transform rounds unknown format");
                }
                read(in, transform_rounds);
                break;

            case FieldID::ENCRYPTION_IV:
                read(in, encryption_iv, length);
                break;

            case FieldID::PROTECTED_STREAM_KEY:
                read(in, protected_stream_key, length);
                break;

            case FieldID::STREAM_START_BYTES:
                read(in, stream_start_bytes, length);
                break;

            case FieldID::INNER_RANDOM_STREAM_ID:
                if (length != sizeof(inner_random_stream_id)) {
                    throw parse_error("inner random stream id unknown format");
                }
                read(in, inner_random_stream_id);
                break;

            default:
                throw parse_error("unknown header field");
        }
    }
}

void kdbx2_pvt::parse_body_v1(istream& in)
{
    // Build the master key
    SecByteBlock master_key(keys.DigestSize());
    keys.Final(master_key.data());

    // Encrypt the key _transform_rounds times
    ECB_Mode<AES>::Encryption key_transform(transform_seed,
                                            transform_seed.size());

    for (uint64_t ii = 0; ii < transform_rounds; ii++) {
        key_transform.ProcessData(master_key.data(),
                                    master_key.data(),
                                    master_key.size());
    }

    // Hash the transformed key
    SHA256 hash;
    hash.Update(master_key.data(), master_key.size());
    hash.Final(master_key.data());

    // Combine the key with the master seed
    hash.Update(master_seed.data(), master_seed.size());
    hash.Update(master_key.data(), master_key.size());
    hash.Final(master_key.data());

    CBC_Mode<AES>::Decryption decryption(master_key,
                                            master_key.size(),
                                            encryption_iv.data());

    string ciphertext;
    read_to_end(in, ciphertext);
    string plaintext;

    StringSource s(ciphertext, true,
        new StreamTransformationFilter(decryption,
            new StringSink(plaintext)
        ) // StreamTransformationFilter
    ); // StringSource

    if (!starts_with(plaintext, stream_start_bytes)) {
        throw parse_error("incorrect password");
    }

    plaintext = plaintext.substr(stream_start_bytes.size());

    // Read the plaintext using a validating stream buffer
    stringstream ss(plaintext);
    hashbuf buffer(ss);
    istream hash_stream(&buffer);

    xml_document& doc = document;
    xml_parse_result result = doc.load(hash_stream);

    if (!result) {
        throw parse_error("XML error: " + string(result.description()));
    }


    xml_node kee = doc.child("KeePassFile");

    // Read the Meta tag
    meta = kee.child("Meta");

    // Read the Root tag
    xml_node root = kee.child("Root");

    for (xml_node child : root) {
        if (!std::strcmp(child.name(), "Group")) {
            groups.emplace_back(_pub, child);
        } else if (!std::strcmp(child.name(), "DeletedObjects")) {
            // TODO: Do something with these
        } else {
            std::cerr << "Unknown root node: " << child.name() << endl;
        }
    }
}

//
// Header
//
uint32_t kdbx2::signature1() const { return _pvt->signature1; }
uint32_t kdbx2::signature2() const { return _pvt->signature2; }
uint32_t kdbx2::file_version() const { return _pvt->file_version; }
uint16_t kdbx2::file_version_minor() const { return _pvt->file_version & 0xFFFF; }
uint16_t kdbx2::file_version_major() const { return static_cast<uint16_t>(_pvt->file_version >> 16); }
const std::string& kdbx2::comment() const { return _pvt->comment; }
const std::string& kdbx2::cipher_id() const { return _pvt->cipher_id; }
uint32_t kdbx2::compression_flags() const { return _pvt->compression_flags; }
uint64_t kdbx2::transform_rounds() const { return _pvt->transform_rounds; }
uint32_t kdbx2::inner_random_stream_id() const { return _pvt->inner_random_stream_id; }

//
// Meta
//
const char* kdbx2::generator() const { return _pvt->meta.child("Generator").text().get(); }
const char* kdbx2::header_hash() const { return _pvt->meta.child("HeaderHash").text().get(); }
const char* kdbx2::database_name() const { return _pvt->meta.child("DatabaseName").text().get(); }
const char* kdbx2::database_name_changed() const { return _pvt->meta.child("DatabaseNameChanged").text().get(); }
const char* kdbx2::database_description() const { return _pvt->meta.child("DatabaseDescription").text().get(); }
const char* kdbx2::database_description_changed() const { return _pvt->meta.child("DatabaseDescriptionChanged").text().get(); }
const char* kdbx2::default_user_name() const { return _pvt->meta.child("DefaultUserName").text().get(); }
const char* kdbx2::default_user_name_changed() const { return _pvt->meta.child("DefaultUserNameChanged").text().get(); }
const char* kdbx2::maintenance_history_days() const { return _pvt->meta.child("MaintenanceHistoryDays").text().get(); }
const char* kdbx2::color() const { return _pvt->meta.child("Color").text().get(); }
const char* kdbx2::master_key_changed() const { return _pvt->meta.child("MasterKeyChanged").text().get(); }
int kdbx2::master_key_change_rec() const { return _pvt->meta.child("MasterKeyChangeRec").text().as_int(); }
int kdbx2::master_key_change_force() const { return _pvt->meta.child("MasterKeyChangeForce").text().as_int(); }
bool kdbx2::recycle_bin_enabled() const { return _pvt->meta.child("RecycleBinEnabled").text().as_bool(); }
const char* kdbx2::recycle_bin_uuid() const { return _pvt->meta.child("RecycleBinUUID").text().get(); }
const char* kdbx2::recycle_bin_changed() const { return _pvt->meta.child("RecycleBinChanged").text().get(); }
const char* kdbx2::entry_templates_group() const { return _pvt->meta.child("EntryTemplatesGroup").text().get(); }
const char* kdbx2::entry_templates_group_changed() const { return _pvt->meta.child("EntryTemplatesGroupChanged").text().get(); }
const char* kdbx2::history_max_items() const { return _pvt->meta.child("HistoryMaxItems").text().get(); }
const char* kdbx2::history_max_size() const { return _pvt->meta.child("HistoryMaxSize").text().get(); }
const char* kdbx2::last_selected_group() const { return _pvt->meta.child("LastSelectedGroup").text().get(); }
const char* kdbx2::last_top_visible_group() const { return _pvt->meta.child("LastTopVisibleGroup").text().get(); }

//
// Groups
//
const std::vector<group>& kdbx2::groups() const { return _pvt->groups; }

}
