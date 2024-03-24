// Copyright (c) 2023, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "cryptonote_basic/account.h"
#include "device/device_cold.hpp"
#include "device_trezor/device_trezor.hpp"
#include "file_io_utils.h"
#include "serialization/binary_utils.h"
#include "storages/portable_storage_template_helper.h"
#include "wallet2_boost_serialization.h"
#include "wallet2_storage.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2_basic.storage"

using namespace boost::archive;
using namespace tools;
using rapidjson::Document;

#define TRY_NOFAIL(stmt) try { stmt; } catch (...) {}

namespace
{
struct cache_file_data
{
    crypto::chacha_iv iv;
    std::string cache_data;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(cache_data)
    END_SERIALIZE()
};

struct keys_file_data
{
    crypto::chacha_iv iv;
    std::string account_data;

    BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
    END_SERIALIZE()
};

static hw::i_device_callback noop_device_cb;

// https://github.com/monero-project/monero/blob/67d190ce7c33602b6a3b804f633ee1ddb7fbb4a1/src/wallet/wallet2.cpp#L156
static constexpr const char WALLET2_ASCII_OUTPUT_MAGIC[] = "MoneroAsciiDataV1";

template <class Archive>
wallet2_basic::cache boost_deserialize_cache(const std::string& cache_data)
{
    wallet2_basic::cache c;
    std::istringstream iss(cache_data);
    Archive ar(iss);
    ar >> c;
    return c;
}

void save_pem_ascii_file(const std::string& path, const std::string& data)
{
    std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(path.c_str(), "w+"), &fclose);
    CHECK_AND_ASSERT_THROW_MES(fp,
        "Failed to open wallet file for writing: " << path << ": " << strerror(errno));

    const unsigned char* const data_uc = reinterpret_cast<const unsigned char*>(data.data());
    CHECK_AND_ASSERT_THROW_MES(PEM_write(fp.get(), WALLET2_ASCII_OUTPUT_MAGIC, "", data_uc, data.size()),
        "Failed to PEM write to file: " << path);
}

std::string load_pem_ascii_string(const std::string& pem_contents)
{
    std::unique_ptr<BIO, decltype(&BIO_free)> bb(BIO_new_mem_buf(pem_contents.data(), pem_contents.size()), &BIO_free);

    char* name = NULL;
    char* header = NULL;
    unsigned char* data = NULL;
    long data_len = 0;
    const bool read_success = PEM_read_bio(bb.get(), &name, &header, &data, &data_len);

    std::string result_data;
    bool alloc_success = false;
    try
    {
        result_data = std::string((const char*) data, data_len);
        alloc_success = true;
    }
    catch (...) {}

    OPENSSL_free((void *) name);
    OPENSSL_free((void *) header);
    OPENSSL_free((void *) data);

    CHECK_AND_ASSERT_THROW_MES(read_success, "Could not read string contents as PEM data");
    CHECK_AND_ASSERT_THROW_MES(alloc_success, "Could not allocate new result string from PEM read");

    return result_data;
}

/***************************************************************************************************
********************************JSON ADAPTER HELPER FUNCTIONS***************************************
***************************************************************************************************/

template <typename T, typename U> void assign_when_mutable(T& dst, const U& src) { dst = src; }
template <typename T, typename U> void assign_when_mutable(const T& dst, const U& src) {}

template <typename T> const T& as_const_ref(T& t) { return t; }

template <typename T> std::enable_if_t<std::is_integral<T>::value || std::is_enum<T>::value>
adapt_json_field(T& out, const Document& json, const char* name, bool mand)
{
    const rapidjson::Value::ConstMemberIterator memb_it = json.FindMember(name);
    if (memb_it != json.MemberEnd())
    {
        if (memb_it->value.IsInt())
            out = static_cast<T>(memb_it->value.GetInt());
        else if (memb_it->value.IsUint())
            out = static_cast<T>(memb_it->value.GetUint());
        else if (memb_it->value.IsUint64())
            out = static_cast<T>(memb_it->value.GetUint64());
        else
            ASSERT_MES_AND_THROW("Field " << name << " found in JSON, but not an int-like number");
    }
    else if (mand)
        ASSERT_MES_AND_THROW("Field " << name << " not found in JSON");
}

void adapt_json_field(std::string& out, const Document& json, const char* name, bool mand)
{
    const rapidjson::Value::ConstMemberIterator memb_it = json.FindMember(name);
    if (memb_it != json.MemberEnd())
    {
        if (memb_it->value.IsString())
            out = std::string(memb_it->value.GetString(), memb_it->value.GetStringLength());
        else
            ASSERT_MES_AND_THROW("Field " << name << " found in JSON, but not " << "String");
    }
    else if (mand)
        ASSERT_MES_AND_THROW("Field " << name << " not found in JSON");
}

// Load arbitrary types from JSON string fields represented in binary_archive format
template <typename T> std::enable_if_t<!std::is_integral<T>::value && !std::is_enum<T>::value>
adapt_json_field(T& out, const Document& json, const char* name, bool mand)
{
    std::string binary_repr;
    adapt_json_field(binary_repr, json, name, mand);
    const bool r = serialization::parse_binary(binary_repr, out);
    CHECK_AND_ASSERT_THROW_MES(r, "Could not parse object from binary archive in JSON field");
}

template <typename T> std::enable_if_t<std::is_integral<T>::value || std::is_enum<T>::value>
adapt_json_field(const T& in, Document& json, const char* name, bool)
{
    rapidjson::Value k(name, json.GetAllocator());
    rapidjson::Value v;
    if (in < T{}) // Is negative?
        v.SetInt(static_cast<int>(in));
    else // Is positive
        v.SetUint64(static_cast<uint64_t>(in));
    json.AddMember(k, v, json.GetAllocator());
}

void adapt_json_field(const std::string& in, Document& json, const char* name, bool)
{
    rapidjson::Value k(name, json.GetAllocator());
    rapidjson::Value v(in.data(), in.size(), json.GetAllocator());
    json.AddMember(k, v, json.GetAllocator());
}

// Store arbitrary types to JSON string fields represented in binary_archive format
template <typename T> std::enable_if_t<!std::is_integral<T>::value && !std::is_enum<T>::value>
adapt_json_field(const T& in, Document& json, const char* name, bool)
{
    std::string binary_repr;
    const bool r = serialization::dump_binary(const_cast<T&>(in), binary_repr);
    CHECK_AND_ASSERT_THROW_MES(r, "Could not represent object in binary archive");
    adapt_json_field(as_const_ref(binary_repr), json, name, true);
}

template <typename T>
void adapt_json_field(const T&, const Document&, const char*, bool)
{}

} // anonymous namespace

namespace wallet2_basic
{
template <bool SAVING>
void adapt_keysdata_tofrom_json_object
(
    detail::reference_mutate_enabled<keys_data, !SAVING> kd,
    detail::reference_mutate_enabled<rapidjson::Document, SAVING> obj,
    const crypto::chacha_key& keys_key,
    bool downgrade_to_watch_only
);

/***************************************************************************************************
*************************************CACHE STORAGE**************************************************
***************************************************************************************************/
crypto::chacha_key cache::pwd_to_cache_key(const char* pwd, size_t len, uint64_t kdf_rounds)
{
    static_assert(crypto::HASH_SIZE == sizeof(crypto::chacha_key), "Mismatched sizes of hash and chacha key");

    crypto::chacha_key key;
    crypto::generate_chacha_key(pwd, len, key, kdf_rounds);

    epee::mlocked<tools::scrubbed_arr<char, crypto::HASH_SIZE+1>> cache_key_data;
    memcpy(cache_key_data.data(), &key, crypto::HASH_SIZE);
    cache_key_data[crypto::HASH_SIZE] = config::HASH_KEY_WALLET_CACHE;
    crypto::cn_fast_hash(cache_key_data.data(), crypto::HASH_SIZE+1, reinterpret_cast<crypto::hash&>(key));

    return key;
}

crypto::chacha_key cache::account_to_old_cache_key(const cryptonote::account_base& account, uint64_t kdf_rounds)
{
    crypto::chacha_key key;
    hw::device &hwdev = account.get_device();
    const bool r = hwdev.generate_chacha_key(account.get_keys(), key, kdf_rounds);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "device failed to generate chacha key");
    return key;
}

cache cache::load_from_memory
(
    const std::string& cache_file_buf,
    const epee::wipeable_string& password,
    const cryptonote::account_base& wallet_account,
    uint64_t kdf_rounds
)
{
    // Try to deserialize cache file buf into `cache_file_data` type. If success,
    // then we are dealing with encrypted cache
    cache_file_data cfd;
    const bool encrypted_cache = ::serialization::parse_binary(cache_file_buf, cfd);

    if (encrypted_cache)
    {
        LOG_PRINT_L1("Taking encrypted wallet cache load path...");

        // Decrypt cache contents into buffer
        crypto::chacha_key cache_key = pwd_to_cache_key(password.data(), password.size(), kdf_rounds);
        std::string cache_data;
        cache_data.resize(cfd.cache_data.size());
        crypto::chacha20(cfd.cache_data.data(), cfd.cache_data.size(), cache_key, cfd.iv, &cache_data[0]);

        LOG_PRINT_L1("Trying to read from recent binary archive");
        try
        {
            cache c;
            binary_archive<false> ar{epee::strspan<std::uint8_t>(cache_data)};
            if (::serialization::serialize(ar, c))
                if (::serialization::check_stream_state(ar))
                    return c;
        }
        catch (...) {}

        LOG_PRINT_L1("Trying to read from binary archive with varint incompatibility");
        try
        {
            cache c;
            binary_archive<false> ar{epee::strspan<std::uint8_t>(cache_data)};
            ar.enable_varint_bug_backward_compatibility();
            if (::serialization::serialize(ar, c))
                if (::serialization::check_stream_state(ar))
                    return c;
        }
        catch (...) {}

        LOG_PRINT_L1("Trying to read from boost portable binary archive");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_portable_binary_iarchive>(cache_data));

        LOG_PRINT_L1("Switching to decryption key derived from account keys...");
        cache_key = account_to_old_cache_key(wallet_account, kdf_rounds);
        crypto::chacha20(cfd.cache_data.data(), cfd.cache_data.size(), cache_key, cfd.iv, &cache_data[0]);

        LOG_PRINT_L1("Trying to read from boost portable binary archive encrypted with account keys");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_portable_binary_iarchive>(cache_data));

        LOG_PRINT_L1("Switching to old chacha8 encryption...");
        crypto::chacha8(cfd.cache_data.data(), cfd.cache_data.size(), cache_key, cfd.iv, &cache_data[0]);

        LOG_PRINT_L1("Trying to read from boost portable binary archive encrypted with account keys & chacha8");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_portable_binary_iarchive>(cache_data));

        LOG_PRINT_L1("Trying to read from boost UNportable binary archive encrypted with account keys & chacha8");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_binary_iarchive>(cache_data));
    }
    else // not encrypted cache
    {
        LOG_PRINT_L1("Taking unencrypted wallet cache load path...");

        LOG_PRINT_L1("Trying to read from boost portable binary archive unencrypted");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_portable_binary_iarchive>(cache_file_buf));

        LOG_PRINT_L1("Trying to read from boost UNportable binary archive unencrypted");
        TRY_NOFAIL(return boost_deserialize_cache<polymorphic_binary_iarchive>(cache_file_buf));
    }

    THROW_WALLET_EXCEPTION(error::wallet_internal_error, "failed to load wallet cache");
}

std::string cache::store_to_memory(const epee::wipeable_string& password, uint64_t kdf_rounds) const
{
    return store_to_memory(pwd_to_cache_key(password.data(), password.size(), kdf_rounds));
}

std::string cache::store_to_memory(const crypto::chacha_key& encryption_key) const
{
    // Serialize cache
    std::stringstream oss;
    binary_archive<true> ar1(oss);
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar1, const_cast<cache&>(*this)),
        error::wallet_internal_error, "Failed to serialize cache");

    // Prepare outer cache_file_data data structure
    std::string cache_pt = oss.str();
    cache_file_data cfd;
    cfd.iv = crypto::rand<crypto::chacha_iv>();
    cfd.cache_data.resize(cache_pt.size());

    // Encrypt cache
    crypto::chacha20(cache_pt.data(), cache_pt.size(), encryption_key, cfd.iv, &cfd.cache_data[0]);

    // Serialize cache_file_data structure
    oss.str("");
    binary_archive<true> ar2(oss);
    THROW_WALLET_EXCEPTION_IF(!::serialization::serialize(ar2, cfd),
        error::wallet_internal_error, "Failed to serialize outer cache file data");

    return oss.str();
}

/***************************************************************************************************
*********************************WALLET KEYS STORAGE************************************************
***************************************************************************************************/

crypto::chacha_key keys_data::pwd_to_keys_data_key(const char* pwd, size_t len, uint64_t kdf_rounds)
{
    crypto::chacha_key key;
    crypto::generate_chacha_key(pwd, len, key, kdf_rounds);
    return key;
}

keys_data keys_data::load_from_memory
(
    const std::string& keys_file_buf,
    const epee::wipeable_string& password,
    cryptonote::network_type nettype,
    uint64_t kdf_rounds
)
{
    const crypto::chacha_key encryption_key = pwd_to_keys_data_key(password.data(), password.size(), kdf_rounds);
    return load_from_memory(keys_file_buf, encryption_key, nettype);
}

keys_data keys_data::load_from_memory
(
    const std::string& keys_file_buf,
    const crypto::chacha_key& encryption_key,
    cryptonote::network_type nettype
)
{
    // Deserialize encrypted data and IV into `keys_file_data` structure
    keys_file_data kfd;
    bool r = ::serialization::parse_binary(keys_file_buf, kfd);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "internal error: failed to deserialize keys buffer");

    // Derive chacha decryption key from password and decrypt key buffer
    std::string decrypted_keys_data;
    decrypted_keys_data.resize(kfd.account_data.size());
    crypto::chacha20(kfd.account_data.data(), kfd.account_data.size(), encryption_key, kfd.iv, &decrypted_keys_data[0]);

    rapidjson::Document json;
    if (json.Parse(decrypted_keys_data.c_str()).HasParseError() || !json.IsObject())
        crypto::chacha8(kfd.account_data.data(), kfd.account_data.size(), encryption_key, kfd.iv, &decrypted_keys_data[0]);

    keys_data kd;
    kd.m_nettype = nettype;

    if (json.Parse(decrypted_keys_data.c_str()).HasParseError())
    {
        CHECK_AND_ASSERT_THROW_MES(nettype != cryptonote::UNDEFINED,
            "No network type was provided and we can't deduce nettype from old wallet keys files");
        kd.is_old_file_format = true;
        r = epee::serialization::load_t_from_binary(kd.m_account, decrypted_keys_data);
        THROW_WALLET_EXCEPTION_IF(!r, error::invalid_password);
    }
    else if (json.IsObject()) // The contents should be JSON if the wallet follows the new format.
    {
        adapt_keysdata_tofrom_json_object<false>(kd, json, encryption_key, false);
    }
    else
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error,
            "malformed wallet keys JSON: Document root is not an object");
    }

    return kd;
}

std::string keys_data::store_to_memory
(
    const epee::wipeable_string& password,
    bool downgrade_to_watch_only,
    uint64_t kdf_rounds
) const
{
    const crypto::chacha_key encryption_key = pwd_to_keys_data_key(password.data(), password.size(), kdf_rounds);
    return store_to_memory(encryption_key, downgrade_to_watch_only);
}

std::string keys_data::store_to_memory
(
    const crypto::chacha_key& encryption_key,
    bool downgrade_to_watch_only
) const
{
    // Create JSON object containing all the information we need about our keys data
    rapidjson::Document json;
    json.SetObject();
    adapt_keysdata_tofrom_json_object<true>(*this, json, encryption_key, downgrade_to_watch_only);

    // Serialize the JSON object
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    json.Accept(writer);

    // Encrypt the JSON buffer into a keys_file_data structure
    keys_file_data kfd;
    kfd.account_data.resize(buffer.GetSize());
    kfd.iv = crypto::rand<crypto::chacha_iv>();
    crypto::chacha20(buffer.GetString(), buffer.GetSize(), encryption_key, kfd.iv, &kfd.account_data[0]);

    // Serialize the keys_file_data structure as a binary archive
    std::string final_buf;
    const bool r = ::serialization::dump_binary(kfd, final_buf);
    CHECK_AND_ASSERT_THROW_MES(r, "Failed to serialize keys_file_data into binary archive");

    return final_buf;
}

void keys_data::setup_account_keys_and_devices
(
    const epee::wipeable_string& password,
    hw::i_device_callback* device_cb,
    uint64_t kdf_rounds
)
{
    const crypto::chacha_key encryption_key = pwd_to_keys_data_key(password.data(), password.size(), kdf_rounds);
    setup_account_keys_and_devices(encryption_key, device_cb);
}

void keys_data::setup_account_keys_and_devices
(
    const crypto::chacha_key& encryption_key,
    hw::i_device_callback* device_cb
)
{
    if (m_key_device_type == hw::device::device_type::LEDGER || m_key_device_type == hw::device::device_type::TREZOR)
    {
        LOG_PRINT_L0("Account on device. Initing device...");
        hw::device &hwdev = reconnect_device(device_cb);

        cryptonote::account_public_address device_account_public_address;
        bool fetch_device_address = true;

        ::hw::device_cold* dev_cold = nullptr;
        if (m_key_device_type == hw::device::device_type::TREZOR && (dev_cold = dynamic_cast<::hw::device_cold*>(&hwdev)) != nullptr)
        {
            THROW_WALLET_EXCEPTION_IF(
                !dev_cold->get_public_address_with_no_passphrase(device_account_public_address),
                error::wallet_internal_error, "Cannot get a device address");
            if (device_account_public_address == m_account.get_keys().m_account_address)
            {
                LOG_PRINT_L0("Wallet opened with an empty passphrase");
                fetch_device_address = false;
                dev_cold->set_use_empty_passphrase(true);
            }
            else
            {
                fetch_device_address = true;
                LOG_PRINT_L0("Wallet opening with an empty passphrase failed. Retry again: " << fetch_device_address);
                dev_cold->reset_session();
            }
        }

        if (fetch_device_address)
        {
            THROW_WALLET_EXCEPTION_IF(!hwdev.get_public_address(device_account_public_address),
                error::wallet_internal_error, "Cannot get a device address");
        }

        THROW_WALLET_EXCEPTION_IF(device_account_public_address != m_account.get_keys().m_account_address,
            error::wallet_internal_error,
            "Device wallet does not match wallet address. If the device uses the passphrase feature, "
            "please check whether the passphrase was entered correctly (it may have been misspelled - "
            "different passphrases generate different wallets, passphrase is case-sensitive). "
            "Device address: " + cryptonote::get_account_address_as_str(m_nettype, false, device_account_public_address) +
            ", wallet address: " + m_account.get_public_address_str(m_nettype));
        LOG_PRINT_L0("Device inited...");
    }
    else if (requires_external_device())
    {
        THROW_WALLET_EXCEPTION(error::wallet_internal_error, "hardware device not supported");
    }

    hw::device& hwdev = m_account.get_keys().get_device();
    const bool view_only = m_watch_only || m_multisig || hwdev.device_protocol() == hw::device::PROTOCOL_COLD;
    const bool keys_verified = verify_account_keys(view_only);
    CHECK_AND_ASSERT_THROW_MES(keys_verified, "Device does not appear to correspond to this wallet file");
}

bool keys_data::verify_account_keys
(
    bool view_only,
    hw::device* alt_device
) const
{
    return wallet2_basic::verify_account_keys(m_account.get_keys(), view_only, alt_device);
}

hw::device& keys_data::reconnect_device(hw::i_device_callback* device_cb)
{
#ifdef WITH_DEVICE_TREZOR
    hw::trezor::register_all();
#endif
    hw::device& hwdev = hw::get_device(m_device_name);

    THROW_WALLET_EXCEPTION_IF(!hwdev.set_name(m_device_name), error::wallet_internal_error,
        "Could not set device name " + m_device_name);
    hwdev.set_network_type(m_nettype);
    hwdev.set_derivation_path(m_device_derivation_path);
    hwdev.set_callback(device_cb ? device_cb : &noop_device_cb);
    THROW_WALLET_EXCEPTION_IF(!hwdev.init(), error::wallet_internal_error,
        "Could not initialize the device " + m_device_name);
    THROW_WALLET_EXCEPTION_IF(!hwdev.connect(), error::wallet_internal_error,
        "Could not connect to the device " + m_device_name);
    m_account.set_device(hwdev);

    return hwdev;
}

#define ADAPT_JSON_FIELD_N(name, jtype, mandatory, var)                                                  \
    do {                                                                                                 \
        detail::reference_mutate_enabled<std::remove_reference_t<decltype(var)>, !SAVING> var_ref = var; \
        adapt_json_field(var_ref, obj, #name, mandatory);                                                \
    } while (0);                                                                                         \

#define ADAPT_JSON_FIELD(name, jtype, mandatory)            \
    ADAPT_JSON_FIELD_N(name, jtype, mandatory, kd.m_##name) \

template <bool SAVING>
void adapt_keysdata_tofrom_json_object
(
    detail::reference_mutate_enabled<keys_data, !SAVING> kd,
    detail::reference_mutate_enabled<rapidjson::Document, SAVING> obj,
    const crypto::chacha_key& keys_key,
    bool downgrade_to_watch_only
)
{
    // Important prereq: we assume we already know obj is an object and not an array, number, etc

    // We always encrypt the account when storing now, but very old wallets didn't
    bool account_keys_are_encrypted = SAVING;
    ADAPT_JSON_FIELD_N(encrypted_secret_keys, Int, false, account_keys_are_encrypted);
    assign_when_mutable(kd.m_keys_were_encrypted_on_load, account_keys_are_encrypted);

    if (SAVING) // Saving account to JSON
    {
        cryptonote::account_base encrypted_account = kd.m_account;
        if (downgrade_to_watch_only)
            encrypted_account.forget_spend_key();
        encrypted_account.encrypt_keys(keys_key);
        const epee::byte_slice account_data_slice = epee::serialization::store_t_to_binary(encrypted_account);
        const std::string account_data(reinterpret_cast<const char*>(account_data_slice.data()), account_data_slice.size());
        ADAPT_JSON_FIELD_N(key_data, String, true, account_data);
    }
    else // Loading account from JSON
    {
        std::string account_data;
        ADAPT_JSON_FIELD_N(key_data, String, true, account_data);
        cryptonote::account_base decrypted_account;
        CHECK_AND_ASSERT_THROW_MES(
            epee::serialization::load_t_from_binary(decrypted_account, account_data),
            "Could not parse account keys from EPEE binary");
        if (account_keys_are_encrypted)
            decrypted_account.decrypt_keys(keys_key);
        assign_when_mutable(kd.m_account, decrypted_account);
    }

    ADAPT_JSON_FIELD(nettype, Uint, kd.m_nettype == cryptonote::UNDEFINED);
    CHECK_AND_ASSERT_THROW_MES(
        kd.m_nettype == cryptonote::MAINNET ||
        kd.m_nettype == cryptonote::TESTNET ||
        kd.m_nettype == cryptonote::STAGENET ||
        kd.m_nettype == cryptonote::FAKECHAIN,
        "unrecognized network type for keys_data");

    ADAPT_JSON_FIELD(multisig, Int, false);
    ADAPT_JSON_FIELD(multisig_threshold, Uint, kd.m_multisig);
    ADAPT_JSON_FIELD(multisig_rounds_passed, Uint, false);
    ADAPT_JSON_FIELD(enable_multisig, Int, false);
    ADAPT_JSON_FIELD(multisig_signers, binary_archive, kd.m_multisig);
    ADAPT_JSON_FIELD(multisig_derivations, binary_archive, false);

    ADAPT_JSON_FIELD(watch_only, Int, false);
    ADAPT_JSON_FIELD(confirm_non_default_ring_size, Int, false);
    ADAPT_JSON_FIELD(ask_password, Int, false); // @TODO: Check AskPasswordType
    ADAPT_JSON_FIELD(refresh_type, Int, false); // @TODO: Check RefreshType
    ADAPT_JSON_FIELD(skip_to_height, Uint64, false);
    ADAPT_JSON_FIELD(max_reorg_depth, Uint64, false);
    ADAPT_JSON_FIELD(min_output_count, Uint, false);
    ADAPT_JSON_FIELD(min_output_value, Uint64, false);
    ADAPT_JSON_FIELD(merge_destinations, Int, false);
    ADAPT_JSON_FIELD(confirm_backlog, Int, false);
    ADAPT_JSON_FIELD(confirm_backlog_threshold, Uint, false);
    ADAPT_JSON_FIELD(confirm_export_overwrite, Int, false);
    ADAPT_JSON_FIELD(auto_low_priority, Int, false);
    ADAPT_JSON_FIELD(confirm_export_overwrite, Int, false);
    ADAPT_JSON_FIELD(segregate_pre_fork_outputs, Int, false);
    ADAPT_JSON_FIELD(key_reuse_mitigation2, Int, false);
    ADAPT_JSON_FIELD(segregation_height, Uint, false);
    ADAPT_JSON_FIELD(ignore_fractional_outputs, Int, false);
    ADAPT_JSON_FIELD(ignore_outputs_above, Uint64, false);
    ADAPT_JSON_FIELD(ignore_outputs_below, Uint64, false);
    ADAPT_JSON_FIELD(track_uses, Int, false);
    ADAPT_JSON_FIELD(show_wallet_name_when_locked, Int, false);
    ADAPT_JSON_FIELD(inactivity_lock_timeout, Uint, false);
    ADAPT_JSON_FIELD(setup_background_mining, Int, false);
    ADAPT_JSON_FIELD(subaddress_lookahead_major, Uint, false);
    ADAPT_JSON_FIELD(subaddress_lookahead_minor, Uint, false);
    ADAPT_JSON_FIELD(always_confirm_transfers, Int, false);
    ADAPT_JSON_FIELD(print_ring_members, Int, false);
    ADAPT_JSON_FIELD(store_tx_info, Int, false);
    ADAPT_JSON_FIELD(default_mixin, Uint, false);
    ADAPT_JSON_FIELD(export_format, Int, false); // @TODO Check ExportFormat
    ADAPT_JSON_FIELD(load_deprecated_formats, Int, false);
    ADAPT_JSON_FIELD(default_priority, Uint, false);
    ADAPT_JSON_FIELD(auto_refresh, Int, false);
    ADAPT_JSON_FIELD(device_derivation_path, String, false);

    ADAPT_JSON_FIELD_N(store_tx_keys, Int, false, kd.m_store_tx_info); // backward compat
    ADAPT_JSON_FIELD_N(default_fee_multiplier, Uint, false, kd.m_default_priority); // backward compat
    ADAPT_JSON_FIELD_N(refresh_height, Uint64, false, kd.m_refresh_from_block_height);
    ADAPT_JSON_FIELD_N(key_on_device, Int, false, kd.m_key_device_type);
    ADAPT_JSON_FIELD_N(seed_language, String, false, kd.seed_language);

    assign_when_mutable(kd.m_device_name, (kd.m_key_device_type == hw::device::device_type::LEDGER) ? "Ledger" : "default");
    ADAPT_JSON_FIELD(device_name, String, false);

    ADAPT_JSON_FIELD(original_keys_available, Int, false);
    if (kd.m_original_keys_available)
    {
        std::string original_address, original_view_secret_key;
        if (SAVING)
        {
            original_address = get_account_address_as_str(kd.m_nettype, false, kd.m_original_address);
            ADAPT_JSON_FIELD_N(original_address, String, true, original_address);
            original_view_secret_key = epee::string_tools::pod_to_hex(kd.m_original_view_secret_key);
            ADAPT_JSON_FIELD_N(original_view_secret_key, String, true, original_view_secret_key);
        }
        else // loading original address
        {
            ADAPT_JSON_FIELD_N(original_address, String, true, original_address);
            cryptonote::address_parse_info info;
            CHECK_AND_ASSERT_THROW_MES(get_account_address_from_str(info, kd.m_nettype, original_address),
                "Failed to parse original_address from JSON");
            assign_when_mutable(kd.m_original_address, info.address);

            ADAPT_JSON_FIELD_N(original_view_secret_key, String, true, original_view_secret_key);
            crypto::secret_key original_view_secret_key_pod;
            CHECK_AND_ASSERT_THROW_MES(
                epee::string_tools::hex_to_pod(original_view_secret_key, original_view_secret_key_pod),
                "Failed to parse original_view_secret_key from JSON");
            assign_when_mutable(kd.m_original_view_secret_key, original_view_secret_key_pod);
        }
    }
}

/***************************************************************************************************
********************************** MISC ACCOUNT UTILS  *********************************************
***************************************************************************************************/

bool verify_account_keys
(
    const cryptonote::account_keys& keys,
    bool view_only,
    hw::device* hwdev
)
{
    if (nullptr == hwdev)
    {
        hwdev = std::addressof(keys.get_device());
        CHECK_AND_ASSERT_THROW_MES(hwdev, "Account device is NULL and no alternate was provided");
    }

    if (!hwdev->verify_keys(keys.m_view_secret_key,  keys.m_account_address.m_view_public_key))
        return false;

    if (!view_only)
        if (!hwdev->verify_keys(keys.m_spend_secret_key, keys.m_account_address.m_spend_public_key))
            return false;

    return true;
}

/***************************************************************************************************
********************* WALLET KEYS/CACHE COMBINATION LOADING/STORING ********************************
***************************************************************************************************/

void load_keys_and_cache_from_memory
(
    const std::string& cache_file_buf,
    const std::string& keys_file_buf,
    const epee::wipeable_string& password,
    cache& c,
    keys_data& k,
    cryptonote::network_type nettype,
    bool allow_external_devices_setup,
    hw::i_device_callback* device_cb,
    uint64_t kdf_rounds
)
{
    k = keys_data::load_from_memory(keys_file_buf, password, nettype, kdf_rounds);
    if (!k.requires_external_device() || allow_external_devices_setup)
    {
        k.setup_account_keys_and_devices(password, device_cb, kdf_rounds);
    }
    c = cache::load_from_memory(cache_file_buf, password, k.m_account, kdf_rounds);
}

void load_keys_and_cache_from_file
(
    const std::string& cache_path,
    const epee::wipeable_string& password,
    cache& c,
    keys_data& k,
    cryptonote::network_type nettype,
    std::string keys_path,
    bool allow_external_devices_setup,
    hw::i_device_callback* device_cb,
    uint64_t kdf_rounds
)
{
    if (keys_path.empty())
    {
        keys_path = cache_path + ".keys";
    }

    std::string keys_file_contents;
    CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::load_file_to_string(keys_path, keys_file_contents),
        "Could not load keys wallet file: " << keys_path);

    try
    {
        k = keys_data::load_from_memory(keys_file_contents, password, nettype, kdf_rounds);
    }
    catch (...)
    {
        keys_file_contents = load_pem_ascii_string(keys_file_contents);
        k = keys_data::load_from_memory(keys_file_contents, password, nettype, kdf_rounds);
    }
    
    if (!k.requires_external_device() || allow_external_devices_setup)
    {
        k.setup_account_keys_and_devices(password, device_cb, kdf_rounds);
    }

    std::string cache_file_buf;
    const bool loaded_cache = epee::file_io_utils::load_file_to_string(cache_path, cache_file_buf);

    if (loaded_cache)
    {
        c = cache::load_from_memory(cache_file_buf, password, k.m_account, kdf_rounds);
    }
    else
    {
        MWARNING("Could not load cache from filesystem, returning default cache");
        c = cache();
    }
}

void store_keys_and_cache_to_memory
(
    const cache& c,
    const keys_data& k,
    const epee::wipeable_string& password,
    std::string& cache_buf,
    std::string& keys_buf,
    uint64_t kdf_rounds
)
{
    cache_buf = c.store_to_memory(password, kdf_rounds);
    keys_buf = k.store_to_memory(password, false, kdf_rounds);
}

void store_keys_and_cache_to_file
(
    const cache& c,
    const keys_data& k,
    const epee::wipeable_string& password,
    const std::string& cache_path,
    uint64_t kdf_rounds,
    ExportFormat keys_file_format
)
{
    const std::string keys_path = cache_path + ".keys";
    
    std::string file_buf = c.store_to_memory(password, kdf_rounds);
    CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(cache_path, file_buf),
        "could not save cache data to path '" << cache_path << "'");
    
    file_buf = k.store_to_memory(password, false, kdf_rounds);

    if (keys_file_format == Binary)
    {
        CHECK_AND_ASSERT_THROW_MES(epee::file_io_utils::save_string_to_file(keys_path, file_buf),
            "could not save keys data to path '" << keys_path << "'");
    }
    else // keys_file_format == Ascii
    {
        save_pem_ascii_file(keys_path, file_buf);
    }
}
} // namespace wallet2_basic
