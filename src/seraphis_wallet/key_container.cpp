// paired header
#include "key_container.h"

// local headers
#include "crypto/chacha.h"
#include "misc_log_ex.h"
#include "ringct/rctOps.h"
#include "seraphis_core/jamtis_core_utils.h"
#include "seraphis_core/sp_core_enote_utils.h"
#include "jamtis_keys.h"
#include "seraphis_wallet/encrypted_file.h"

// standard headers

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis_wallet"

namespace seraphis_wallet
{
//-------------------------------------------------------------------------------------------------------------------
// INTERNAL
static jamtis_keys ser_keys_to_jamtis(ser_jamtis_keys const &keys)
{
    return jamtis_keys{
        .k_m = keys.k_m,
        .k_vb = keys.k_vb,
        .xk_ua = keys.xk_ua,
        .xk_fr = keys.xk_fr,
        .s_ga = keys.s_ga,
        .s_ct = keys.s_ct,
        .K_1_base = keys.K_1_base,
        .xK_ua = keys.xK_ua,
        .xK_fr = keys.xK_fr,
    };
}
//-------------------------------------------------------------------------------------------------------------------
// INTERNAL
static KeyContainer ser_container_to_usable(ser_KeyContainer const &key_container, const crypto::chacha_key &key)
{
    return KeyContainer(ser_keys_to_jamtis(key_container.keys), key_container.encrypted, key_container.encryption_iv);
}
//-------------------------------------------------------------------------------------------------------------------
bool jamtis_keys_valid(jamtis_keys const &keys)
{
    jamtis_keys test_keys{keys};

    sp::jamtis::make_jamtis_unlockamounts_key(test_keys.k_vb, test_keys.xk_ua);
    sp::jamtis::make_jamtis_findreceived_key(test_keys.k_vb, test_keys.xk_fr);
    sp::jamtis::make_jamtis_generateaddress_secret(test_keys.k_vb, test_keys.s_ga);
    sp::jamtis::make_jamtis_ciphertag_secret(test_keys.s_ga, test_keys.s_ct);
    sp::make_seraphis_spendkey(test_keys.k_vb, test_keys.k_m, test_keys.K_1_base);
    sp::jamtis::make_jamtis_unlockamounts_pubkey(test_keys.xk_ua, test_keys.xK_ua);
    sp::jamtis::make_jamtis_findreceived_pubkey(test_keys.xk_fr, test_keys.xK_ua, test_keys.xK_fr);

    return test_keys == keys;
}
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(jamtis_keys &&keys, const crypto::chacha_key &key)
    : m_keys{keys}, m_encrypted{false}, m_encryption_iv{}
{
    encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyContainer::KeyContainer(jamtis_keys &&keys, bool encrypted, const crypto::chacha_iv encryption_iv)
    : m_keys{keys}, m_encrypted{encrypted}, m_encryption_iv{encryption_iv}
{
}
//-------------------------------------------------------------------------------------------------------------------
boost::optional<KeyContainer> KeyContainer::load_from(const std::string &path, const crypto::chacha_key &key)
{
    ser_KeyContainer ser_key_container;

    if (!read_encrypted_file(path, key, ser_key_container))
        return {};

    const KeyContainer key_container = ser_container_to_usable(ser_key_container, key);

    if (!jamtis_keys_valid(key_container.m_keys))
    {
        return boost::none;
    }

    return key_container;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::encrypt(const crypto::chacha_key &key)
{
    if (m_encrypted)
        return false;

    m_encryption_iv = crypto::rand<crypto::chacha_iv>();

    m_keys.encrypt(key, m_encryption_iv);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::decrypt(const crypto::chacha_key &key)
{
    if (!m_encrypted)
        return false;

    m_keys.decrypt(key, m_encryption_iv);
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
const jamtis_keys &KeyContainer::get_keys()
{
    return m_keys;
}
//-------------------------------------------------------------------------------------------------------------------
void KeyContainer::set_keys(jamtis_keys &&keys, const crypto::chacha_key &key)
{
    m_keys = keys;
    m_encrypted = false;

    encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_all(const std::string &path, const crypto::chacha_key &key)
{
    ser_jamtis_keys ser_keys = {
        .k_m = m_keys.k_m,
        .k_vb = m_keys.k_vb,
        .xk_ua = m_keys.xk_ua,
        .xk_fr = m_keys.xk_fr,
        .s_ga = m_keys.s_ga,
        .s_ct = m_keys.s_ct,
        .K_1_base = m_keys.K_1_base,
        .xK_ua = m_keys.xK_ua,
        .xK_fr = m_keys.xK_fr,
    };

    return write_encrypted_file(path, key, ser_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_only(const std::string &path, const crypto::chacha_key &key)
{
    if (m_encrypted)
        return false;

    ser_jamtis_keys view_only_keys = {
        .k_m = {},
        .k_vb = {},
        .xk_ua = {},
        .xk_fr = m_keys.xk_fr,
        .s_ga = {},
        .s_ct = {},
        .K_1_base = {},
        .xK_ua = m_keys.xK_ua,
        .xK_fr = m_keys.xK_fr,
    };

    // const ser_KeyContainer ser = {
    //     .keys = ser_jamtis_keys{m_keys},
    //     .encrypted = m_encrypted,
    //     .encryption_iv = m_encryption_iv,
    // };

    return write_encrypted_file(path, key, view_only_keys);
}
//-------------------------------------------------------------------------------------------------------------------
bool KeyContainer::write_view_balance(const std::string &path, const crypto::chacha_key &key)
{
    if (m_encrypted)
        return false;

    jamtis_keys view_only_keys;
    view_only_keys = jamtis_keys{
        .k_m = {},
        .k_vb = m_keys.k_vb,
        .xk_ua = {},
        .xk_fr = m_keys.xk_fr,
        .s_ga = {},
        .s_ct = {},
        .K_1_base = {},
        .xK_ua = m_keys.xK_ua,
        .xK_fr = m_keys.xK_fr,
    };

    return write_encrypted_file_json(path, key, view_only_keys);
}
//-------------------------------------------------------------------------------------------------------------------
WalletType KeyContainer::get_wallet_type()
{
    if (m_keys.k_m == rct::rct2sk(rct::zero()))
    {
        if (m_keys.k_vb == rct::rct2sk(rct::zero()))
            return WalletType::ViewOnly;
        else
            return WalletType::ViewBalance;
    }
    return WalletType::Master;
}
//-------------------------------------------------------------------------------------------------------------------
void generate_keys(const crypto::chacha_key &key, KeyContainer &key_container_out)
{
    jamtis_keys keys;
    make_jamtis_keys(keys);

    key_container_out.set_keys(std::move(keys), key);
}
//-------------------------------------------------------------------------------------------------------------------
// KeyGuard
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(const KeyGuard &other) : m_ref{other.m_ref + 1}, m_container{other.m_container}, m_key{other.m_key}
{
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::KeyGuard(KeyContainer &container, const crypto::chacha_key &key)
    : m_container{container}, m_ref{1}, m_key{key}
{
    m_container.encrypt(key);
}
//-------------------------------------------------------------------------------------------------------------------
KeyGuard::~KeyGuard()
{
    if (m_ref == 1)
    {
        m_container.encrypt(m_key);
    }
}
//-------------------------------------------------------------------------------------------------------------------
} // namespace seraphis_wallet
