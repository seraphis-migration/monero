#pragma once

// local headers
#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/hmac-keccak.h"
#include "jamtis_keys.h"
#include "serialization/keyvalue_serialization.h"
#include "serialization/serialization.h"

// third party headers

// standard headers
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// forward declarations

using namespace sp::jamtis;

// NOTE: I don't think this is a good idea.
struct ser_jamtis_keys
{
    crypto::secret_key k_m;          // master
    crypto::secret_key k_vb;         // view-balance
    crypto::x25519_secret_key xk_ua; // unlock-amounts
    crypto::x25519_secret_key xk_fr; // find-received
    crypto::secret_key s_ga;         // generate-address
    crypto::secret_key s_ct;         // cipher-tag
    rct::key K_1_base;               // jamtis spend base     = k_vb X + k_m U
    crypto::x25519_pubkey xK_ua;     // unlock-amounts pubkey = xk_ua xG
    crypto::x25519_pubkey xK_fr;     // find-received pubkey  = xk_fr xk_ua xG

    BEGIN_SERIALIZE()
    FIELD(k_m)
    FIELD(k_vb)
    FIELD(xk_ua)
    FIELD(xk_fr)
    FIELD(s_ga)
    FIELD(s_ct)
    FIELD(K_1_base)
    FIELD(xK_ua)
    FIELD(xK_fr)
    END_SERIALIZE()
};

struct ser_KeyContainer
{
    crypto::chacha_iv encryption_iv;
    ser_jamtis_keys keys;
    bool encrypted;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(keys)
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(encryption_iv)
    KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(encrypted)
    END_KV_SERIALIZE_MAP()
};

BLOB_SERIALIZER(ser_jamtis_keys);
BLOB_SERIALIZER(ser_KeyContainer);

namespace seraphis_wallet
{

enum class WalletType
{
    ViewOnly,
    ViewBalance,
    Master,
};

/// KeyContainer
// contains the keys used for other purposes.
///
class KeyContainer
{
public:
    KeyContainer(jamtis_keys &&keys, const crypto::chacha_key &key);

    KeyContainer() : m_keys{}, m_encryption_iv{}, m_encrypted{false} {}

    KeyContainer(jamtis_keys &&keys,
        bool encrypted,
        const crypto::chacha_iv encryption_iv);

    /// load keys from a file and ensure their validity
    static boost::optional<KeyContainer> load_from(const std::string &path, const crypto::chacha_key &key);

    // member functions
    bool is_encrypted()
    {
        return m_encrypted;
    }

    /// get the keys
    const jamtis_keys &get_keys();

    /// set keys
    void set_keys(jamtis_keys &&keys, const crypto::chacha_key &key);

    /// encrypt the keys in-memory
    bool encrypt(const crypto::chacha_key &key);

    /// decrypt the keys in-memory
    bool decrypt(const crypto::chacha_key &key);

    /// write all encrypted keys to file
    bool write_all(const std::string &path, crypto::chacha_key const &key);

    /// write encrypted view-only keys to file
    bool write_view_only(const std::string &path, const crypto::chacha_key &key);

    /// write encrypted view-balance keys to file
    bool write_view_balance(const std::string &path, const crypto::chacha_key &key);

    /// get the wallet type of the loaded keys
    WalletType get_wallet_type();

    // TODO: return human-readable representations

private:
    crypto::chacha_iv m_encryption_iv;
    epee::mlocked<jamtis_keys> m_keys;
    bool m_encrypted;
};

// TBD
void restore_keys(const std::vector<std::string> &phrase, KeyContainer &key_container_out);

class KeyGuard
{
public:
    KeyGuard(KeyContainer &, const crypto::chacha_key &);

    KeyGuard(const KeyGuard &other);

    ~KeyGuard();

private:
    const crypto::chacha_key &m_key;
    int m_ref;
    KeyContainer &m_container;
};

} // namespace seraphis_wallet
