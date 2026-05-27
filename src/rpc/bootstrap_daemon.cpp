#include "bootstrap_daemon.h"

#include <stdexcept>

#include <boost/thread/locks.hpp>

#include "crypto/crypto.h"
#include "cryptonote_core/cryptonote_core.h"
#include "hardforks/hardforks.h"
#include "misc_log_ex.h"
#include "net/parse.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon.rpc.bootstrap_daemon"

namespace cryptonote
{

  bootstrap_daemon::bootstrap_daemon(
    const cryptonote::network_type &nettype,
    std::function<std::map<std::string, bool>()> get_public_nodes,
    bool rpc_payment_enabled,
    const std::string &proxy)
    : m_nettype(nettype)
    , m_selector(new bootstrap_node::selector_auto(std::move(get_public_nodes)))
    , m_rpc_payment_enabled(rpc_payment_enabled)
  {
    set_proxy(proxy);
  }

  bootstrap_daemon::bootstrap_daemon(
    const cryptonote::network_type &nettype,
    const std::string &address,
    boost::optional<epee::net_utils::http::login> credentials,
    bool rpc_payment_enabled,
    const std::string &proxy)
    : m_nettype(nettype)
    , m_selector(nullptr)
    , m_rpc_payment_enabled(rpc_payment_enabled)
  {
    set_proxy(proxy);
    if (!set_server(address, std::move(credentials)))
    {
      throw std::runtime_error("invalid bootstrap daemon address or credentials");
    }
  }

  std::string bootstrap_daemon::address() const noexcept
  {
    const auto& host = m_http_client.get_host();
    if (host.empty())
    {
      return std::string();
    }
    return host + ":" + m_http_client.get_port();
  }

  boost::optional<std::pair<uint64_t, uint64_t>> bootstrap_daemon::get_height()
  {
    cryptonote::COMMAND_RPC_GET_INFO::request req;
    cryptonote::COMMAND_RPC_GET_INFO::response res;

    if (!invoke_http_json("/getinfo", req, res))
    {
      return boost::none;
    }

    if (res.status != CORE_RPC_STATUS_OK)
    {
      return boost::none;
    }

    return {{res.height, res.target_height}};
  }

  boost::optional<cryptonote::COMMAND_RPC_GET_VERSION::response> bootstrap_daemon::get_version()
  {
    cryptonote::COMMAND_RPC_GET_VERSION::request req;
    cryptonote::COMMAND_RPC_GET_VERSION::response res;

    const bool r = epee::net_utils::invoke_http_json_rpc("/json_rpc", "get_version", req, res, m_http_client, std::chrono::seconds(10));
    if (!handle_result(r, res.status))
    {
      return boost::none;
    }

    if (res.status != CORE_RPC_STATUS_OK)
    {
      return boost::none;
    }

    return boost::optional<cryptonote::COMMAND_RPC_GET_VERSION::response>(res);
  }

  bool bootstrap_daemon::handle_result(bool success, const std::string &status)
  {
    const bool failed = !success || (!m_rpc_payment_enabled && status == CORE_RPC_STATUS_PAYMENT_REQUIRED);
    if (failed && m_selector)
    {
      const std::string current_address = address();
      m_http_client.disconnect();

      const boost::unique_lock<boost::mutex> lock(m_selector_mutex);
      m_selector->handle_result(current_address, !failed);
    }

    return success;
  }

  void bootstrap_daemon::set_proxy(const std::string &address)
  {
    if (!address.empty() && !net::get_tcp_endpoint(address))
    {
      throw std::runtime_error("invalid proxy address format");
    }
    if (!m_http_client.set_proxy(address))
    {
      throw std::runtime_error("failed to set proxy address");
    }
  }

  bool bootstrap_daemon::set_server(const std::string &address, const boost::optional<epee::net_utils::http::login> &credentials /* = boost::none */)
  {
    if (!m_http_client.set_server(address, credentials))
    {
      MERROR("Failed to set bootstrap daemon address " << address);
      return false;
    }

    MINFO("Changed bootstrap daemon address to " << address);
    return true;
  }


  bool bootstrap_daemon::switch_server_if_needed()
  {
    if (m_http_client.is_connected() || !m_selector)
    {
      return true;
    }

    // We want to make sure we connect to a compatible bootstrap daemon
    MINFO("Attempting to switch bootstrap daemon address");
    std::size_t n_attempts = 0;
    while (n_attempts++ < 6)
    {
      MDEBUG("Bootstrap daemon switch attempt " << n_attempts);
      std::string address;
      {
        boost::unique_lock<boost::mutex> lock(m_selector_mutex);
        const auto node = m_selector->next_node();
        if (!node)
          continue;
        if (!this->set_server(node->address, node->credentials))
          continue;
        address = node->address;
      }

      const auto res = this->get_version();
      if (!res)
        continue;
      std::vector<std::pair<uint8_t, uint64_t>> bootstrap_daemon_hfs;
      bootstrap_daemon_hfs.reserve(res->hard_forks.size());
      for (const auto &hf : res->hard_forks)
        bootstrap_daemon_hfs.push_back({hf.hf_version, hf.height});

      // Only connect to a compatible bootstrap daemon
      bool client_is_outdated = false, daemon_is_outdated = false;
      if (!check_fork_version_compatibility(m_nettype, bootstrap_daemon_hfs, res->current_height, res->target_height, &client_is_outdated, &daemon_is_outdated))
      {
        MWARNING("Bootstrap daemon " << address << " is incompatible with our daemon");
        this->handle_result(false, "");
        continue;
      }

      if (client_is_outdated)
        MWARNING("We are connected to a bootstrap daemon that knows of a future hard fork(s) that we do not");
      else if (daemon_is_outdated)
        MWARNING("We are connected to a bootstrap daemon that has not yet updated for the upcoming fork");

      MGINFO("Successfully switched bootstrap daemon to " << address);
      return true;
    }

    MERROR("Could not find compatible bootstrap daemon");
    return false;
  }

}
