/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <set>

#include <rofl/common/caddress.h>
#include <rofl/common/openflow/cofflowmod.h>
#include <rofl/common/openflow/cofgroupmod.h>

#define OFPCML_NO_BUFFER 0xffff

#define GROUP_ID_FUNC_PORT_VLAN(name, type_id)                                 \
  inline uint32_t group_id_##name(uint32_t port_no, uint16_t vid) {            \
    /* FIXME check port_no */                                                  \
    return type_id << 28 | (0x0fff & vid) << 16 | (0xffff & port_no);          \
  }                                                                            \
  struct __##name##_useless__

#define GROUP_ID_FUNC_PORT(name, type_id)                                      \
  inline uint32_t group_id_##name(uint32_t port_no) {                          \
    /* FIXME check port_no */                                                  \
    return type_id << 28 | (0xffff & port_no);                                 \
  }                                                                            \
  struct __##name##_useless__

#define GROUP_ID_FUNC_ID_VLAN(name, type_id)                                   \
  inline uint32_t group_id_##name(uint16_t id, uint16_t vid) {                 \
    return type_id << 28 | (0x0fff & vid) << 16 | id;                          \
  }                                                                            \
  struct __##name##_useless__

#define GROUP_ID_FUNC_ID(name, type_id)                                        \
  inline uint32_t group_id_##name(uint32_t id) {                               \
    return type_id << 28 | (0x0fffffff & id);                                  \
  }                                                                            \
  struct __##name##_useless__

#define GROUP_ID_FUNC_ID_SUBTYPE(name, type_id, subtype_id)                    \
  inline uint32_t group_id_##name(uint16_t index, uint16_t id) {               \
    return type_id << 28 | (0xffff & id) << 12 | (0x3 & subtype_id) << 10 |    \
           (0x03ff & index);                                                   \
  }                                                                            \
  struct __##name##_useless__

namespace rofl {
namespace openflow {

class rofl_ofdpa_fm_driver final {
public:
  rofl_ofdpa_fm_driver();
  ~rofl_ofdpa_fm_driver();

  void set_idle_timeout(uint16_t timeout) { idle_timeout = timeout; }
  uint16_t get_idle_timeout() const { return idle_timeout; }

  void set_max_len(uint16_t max_len) { this->max_len = max_len; }
  uint16_t get_max_len() const { return max_len; }

  inline uint8_t get_group_type(uint32_t group_id) { return group_id >> 28; }

  inline uint16_t get_group_vid(uint32_t group_id) {
    return (group_id >> 16) & 0x0fff; /* FIXME check type_id */
  }

  inline uint32_t get_group_port(uint32_t group_id) {
    return group_id & 0xffff; /* FIXME check type_id */
  }

  GROUP_ID_FUNC_PORT_VLAN(l2_interface, 0);
  GROUP_ID_FUNC_ID(l2_rewrite, 1);
  GROUP_ID_FUNC_ID(l3_unicast, 2);
  GROUP_ID_FUNC_ID_VLAN(l2_multicast, 3);
  GROUP_ID_FUNC_ID_VLAN(l2_flood, 4);
  GROUP_ID_FUNC_ID(l3_interface, 5);
  GROUP_ID_FUNC_ID_VLAN(l3_multicast, 6);
  GROUP_ID_FUNC_ID(l3_ecmp, 7);
  GROUP_ID_FUNC_ID_SUBTYPE(l2_overlay_flood, 8, 0);
  GROUP_ID_FUNC_ID_SUBTYPE(l2_overlay_multicast, 8, 1);
  GROUP_ID_FUNC_PORT(l2_unfiltered_interface, 11);
  GROUP_ID_FUNC_PORT_VLAN(l2_trunk_interface, 12);
  GROUP_ID_FUNC_PORT(l2_trunk_unfiltered_interface, 13);

  /* OF-DPA Flow-Mods */

  // Overlay Tunnel
  cofflowmod enable_overlay_tunnel(uint8_t ofp_version, uint32_t tunnel_id);
  cofflowmod disable_overlay_tunnel(uint8_t ofp_version, uint32_t tunnel_id);

  // VLAN
  cofflowmod enable_port_pvid_ingress(uint8_t ofp_version, uint32_t port_no,
                                      uint16_t vid, uint16_t vrf_id = 0);
  cofflowmod disable_port_pvid_ingress(uint8_t ofp_version, uint32_t port_no,
                                       uint16_t vid);

  cofflowmod enable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no,
                                     uint16_t vid, uint16_t vrf_id = 0);
  cofflowmod disable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no,
                                      uint16_t vid, uint16_t vrf_id = 0);

  cofflowmod enable_port_vid_allow_all(uint8_t ofp_version, uint32_t port_no);
  cofflowmod disable_port_vid_allow_all(uint8_t ofp_version, uint32_t port_no);

  // Termination MAC
  cofflowmod enable_tmac_ipv4_unicast_mac(uint8_t ofp_version, uint32_t in_port,
                                          uint16_t vid, const caddress_ll &mac);
  cofflowmod disable_tmac_ipv4_unicast_mac(uint8_t ofp_version,
                                           uint32_t in_port, uint16_t vid,
                                           const caddress_ll &mac);
  cofflowmod enable_tmac_ipv6_unicast_mac(uint8_t ofp_version, uint32_t in_port,
                                          uint16_t vid, const caddress_ll &mac);
  cofflowmod disable_tmac_ipv6_unicast_mac(uint8_t ofp_version,
                                           uint32_t in_port, uint16_t vid,
                                           const caddress_ll &mac);
  cofflowmod enable_tmac_ipv4_multicast_mac(uint8_t ofp_version);
  cofflowmod disable_tmac_ipv4_multicast_mac(uint8_t ofp_version);
  cofflowmod enable_tmac_ipv6_multicast_mac(uint8_t ofp_version);
  cofflowmod disable_tmac_ipv6_multicast_mac(uint8_t ofp_version);

  // Bridging
  cofflowmod add_bridging_dlf_vlan(uint8_t ofp_version, uint16_t vid,
                                   uint32_t group_id);
  cofflowmod remove_bridging_dlf_vlan(uint8_t ofp_version, uint16_t vid);

  cofflowmod add_bridging_dlf_overlay(uint8_t ofp_version, uint16_t tunnel_id,
                                      uint32_t group_id);
  cofflowmod remove_bridging_dlf_overlay(uint8_t ofp_version,
                                         uint16_t tunnel_id);

  cofflowmod add_bridging_unicast_vlan(uint8_t ofp_version, uint32_t port_no,
                                       uint16_t vid, const cmacaddr &mac,
                                       bool filtered = true, bool lag = false);

  cofflowmod remove_bridging_unicast_vlan(uint8_t ofp_version, uint32_t port_no,
                                          uint16_t vid, const cmacaddr &mac);
  cofflowmod remove_bridging_unicast_vlan_all(uint8_t ofp_version,
                                              uint32_t port_no, uint16_t vid);

  cofflowmod add_bridging_unicast_overlay(uint8_t ofp_version,
                                          uint32_t lport_no, uint32_t tunnel_id,
                                          const cmacaddr &mac);
  cofflowmod remove_bridging_unicast_overlay(uint8_t ofp_version,
                                             uint32_t tunnel_id,
                                             const cmacaddr &mac);
  cofflowmod remove_bridging_unicast_overlay_all_lport(uint8_t ofp_version,
                                                       uint32_t lport_no);
  cofflowmod remove_bridging_unicast_overlay_all_tunnel(uint8_t ofp_version,
                                                        uint32_t tunnel_id);
  cofflowmod add_bridging_multicast_vlan(uint8_t ofp_version, uint32_t index,
                                         uint16_t vid, const cmacaddr &mac);
  cofflowmod remove_bridging_multicast_vlan(uint8_t ofp_version, uint32_t port,
                                            uint16_t vid, const cmacaddr &mac);

  // Unicast Routing
  cofflowmod enable_ipv4_unicast_host(uint8_t ofp_version,
                                      const caddress_in4 &dst, uint32_t group,
                                      bool update = false, uint16_t vrf_id = 0);
  cofflowmod disable_ipv4_unicast_host(uint8_t ofp_version,
                                       const caddress_in4 &dst,
                                       uint16_t vrf_id = 0);

  cofflowmod enable_ipv4_unicast_lpm(uint8_t ofp_version,
                                     const caddress_in4 &dst,
                                     const caddress_in4 &mask, uint32_t group,
                                     bool update = false, uint16_t vrf_id = 0);
  cofflowmod disable_ipv4_unicast_lpm(uint8_t ofp_version,
                                      const caddress_in4 &dst,
                                      const caddress_in4 &mask,
                                      uint16_t vrf_id = 0);

  cofflowmod enable_ipv6_unicast_host(uint8_t ofp_version,
                                      const caddress_in6 &dst, uint32_t group,
                                      bool update = false, uint16_t vrf_id = 0);
  cofflowmod disable_ipv6_unicast_host(uint8_t ofp_version,
                                       const caddress_in6 &dst,
                                       uint16_t vrf_id = 0);

  cofflowmod enable_ipv6_unicast_lpm(uint8_t ofp_version,
                                     const caddress_in6 &dst,
                                     const caddress_in6 &mask, uint32_t group,
                                     bool update = false, uint16_t vrf_id = 0);
  cofflowmod disable_ipv6_unicast_lpm(uint8_t ofp_version,
                                      const caddress_in6 &dst,
                                      const caddress_in6 &mask,
                                      uint16_t vrf_id = 0);
  // Multicast Routing
  cofgroupmod enable_group_l3_multicast(uint8_t ofp_version, uint32_t port_id,
                                        uint16_t vid);
  cofgroupmod disable_group_l3_multicast(uint8_t ofp_version, uint32_t port_id,
                                         uint16_t vid);
  cofflowmod enable_ipv4_multicast_host(uint8_t ofp_version, uint32_t id,
                                        uint16_t vid, const caddress_in4 &dst,
                                        bool update, uint16_t vrf_id = 0);
  cofflowmod disable_ipv4_multicast_host(uint8_t ofp_version,
                                         const caddress_in4 &dst,
                                         uint16_t vrf_id = 0);
  cofflowmod enable_ipv6_multicast_host(uint8_t ofp_version, uint32_t id,
                                        uint16_t vid, const caddress_in6 &dst,
                                        bool update, uint16_t vrf_id = 0);
  cofflowmod disable_ipv6_multicast_host(uint8_t ofp_version,
                                         const caddress_in6 &dst,
                                         uint16_t vrf_id = 0);

  // Policy ACL
  cofflowmod enable_policy_arp(uint8_t ofp_version, bool update = false);

  cofflowmod enable_policy_l2(uint8_t ofp_version, const rofl::caddress_ll &mac,
                              const rofl::caddress_ll &mask);

  cofflowmod enable_policy_specific_lacp(uint8_t ofp_version,
                                         const caddress_ll &eth_src,
                                         const uint16_t timeout_seconds,
                                         const uint32_t in_port);

  cofflowmod disable_policy_l2(uint8_t ofp_version,
                               const rofl::caddress_ll &mac,
                               const rofl::caddress_ll &mask);

  cofflowmod disable_policy_specific_lacp(uint8_t ofp_version,
                                          const uint32_t in_port);

  cofflowmod enable_policy_8021d(uint8_t ofp_version, bool update = false);
  cofflowmod disable_policy_8021d(uint8_t ofp_version);

  cofflowmod enable_policy_broadcast_udp(uint8_t ofp_version, int16_t src_port,
                                         int16_t dst_port);

  cofflowmod enable_policy_vrrp(uint8_t ofp_version);

  cofflowmod enable_policy_ipv4_multicast(uint8_t ofp_version,
                                          const caddress_in4 &dst,
                                          const caddress_in4 &mask);

  cofflowmod enable_policy_ipv6_multicast(uint8_t ofp_version,
                                          const caddress_in6 &dst,
                                          const caddress_in6 &mask);

  cofflowmod enable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                                       const caddress_ll &dst,
                                       uint32_t group_id, uint64_t cookie);

  cofflowmod disable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                                        const caddress_ll &dst,
                                        uint64_t cookie);

  cofflowmod disable_send_to_l2_rewrite_all(uint8_t ofp_version, uint16_t vid,
                                            uint64_t cookie);

  cofflowmod
  enable_policy_acl_generic(uint8_t ofp_version, const cofmatch &matches,
                            bool clear_actions = false, uint32_t meter_id = 0,
                            uint32_t table_id = 0, uint64_t cookie = 0,
                            const cofactions &apply_actions = cofactions(),
                            const cofactions &write_actions = cofactions());

  cofflowmod disable_policy_acl_generic(uint8_t ofp_version,
                                        const cofmatch &matches,
                                        uint64_t cookie);

  // VLAN Egress
  cofflowmod rewrite_vlan_egress(uint8_t ofp_version, uint32_t backup_port,
                                 uint16_t old_vid, uint16_t new_vid);

  cofflowmod remove_rewritten_vlan_egress(uint8_t ofp_version,
                                          uint32_t backup_port,
                                          uint16_t old_vid, uint16_t new_vid);

  // TPID Egress
  cofflowmod set_port_tpid(uint8_t ofp_version, uint32_t port);
  cofflowmod remove_port_tpid(uint8_t ofp_version, uint32_t port);

  /* OF-DPA Group-Mods */
  cofgroupmod enable_group_l2_interface(uint8_t ofp_version, uint32_t port_no,
                                        uint16_t vid, bool untagged = false,
                                        bool update = false);
  cofgroupmod disable_group_l2_interface(uint8_t ofp_version, uint32_t port_no,
                                         uint16_t vid);

  cofgroupmod enable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                   uint32_t port_no);
  cofgroupmod disable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                    uint32_t port_no);

  cofgroupmod enable_group_l2_multicast(uint8_t ofp_version, uint16_t index,
                                        uint16_t vid,
                                        const std::set<uint32_t> &l2_interfaces,
                                        bool modify = false);
  cofgroupmod disable_group_l2_multicast(uint8_t ofp_version, uint16_t index,
                                         uint16_t vid);

  cofgroupmod enable_group_l2_flood(uint8_t ofp_version, uint16_t vid,
                                    uint16_t id,
                                    const std::set<uint32_t> &l2_interfaces,
                                    bool modify = false);
  cofgroupmod disable_group_l2_flood(uint8_t ofp_version, uint16_t vid,
                                     uint16_t id);

  cofgroupmod enable_group_l2_overlay_flood(uint8_t ofp_version,
                                            uint16_t tunnel_id, uint16_t index,
                                            const std::set<uint32_t> &lport_no,
                                            bool modify = false);
  cofgroupmod disable_group_l2_overlay_flood(uint8_t ofp_version,
                                             uint16_t tunnel_id,
                                             uint16_t index);

  cofgroupmod enable_group_l2_overlay_multicast(
      uint8_t ofp_version, uint16_t tunnel_id, uint16_t index,
      const std::set<uint32_t> &lport_no, bool modify = false);
  cofgroupmod disable_group_l2_overlay_multicast(uint8_t ofp_version,
                                                 uint16_t tunnel_id,
                                                 uint16_t index);

  cofgroupmod enable_group_l2_rewrite(
      uint8_t ofp_version, uint32_t id, uint32_t port_group_id,
      uint16_t vid = 0, const cmacaddr src_mac = cmacaddr{"00:00:00:00:00:00"},
      const cmacaddr dst_mac = cmacaddr{"00:00:00:00:00:00"});

  cofgroupmod disable_group_l2_rewrite(uint8_t ofp_version, uint32_t id);

  /* Used to specify IP multipath. */
  cofgroupmod enable_group_l3_ecmp(uint8_t ofp_version, uint32_t id,
                                   const std::set<uint32_t> l3_unicast,
                                   bool modify = false);

  cofgroupmod disable_group_l3_ecmp(uint8_t ofp_version, uint32_t id);

  /* Used for Ethernet next hop configuration. */
  cofgroupmod enable_group_l3_unicast(uint8_t ofp_version, uint32_t id,
                                      const caddress_ll &src_mac,
                                      const cmacaddr &dst_mac,
                                      uint32_t l2_interface,
                                      bool modify = false);

  cofgroupmod disable_group_l3_unicast(uint8_t ofp_version, uint32_t id);

  /* Used for L3 multicast */
  cofgroupmod enable_group_l3_interface(uint8_t ofp_version, uint32_t id,
                                        const caddress_ll &src_mac,
                                        uint32_t l2_interface,
                                        const cmacaddr &dst_mac = cmacaddr{
                                            "00:00:00:00:00:00"});

  cofgroupmod disable_group_l3_interface(uint8_t ofp_version, uint32_t id);

  /* Used for L2 Trunk */
  cofgroupmod enable_group_l2_trunk_interface(uint8_t ofp_version,
                                              uint32_t port_no, uint16_t vid,
                                              bool untagged = false,
                                              bool update = false);
  cofgroupmod disable_group_l2_trunk_interface(uint8_t ofp_version,
                                               uint32_t port_no, uint16_t vid);

  cofgroupmod enable_group_l2_trunk_unfiltered_interface(uint8_t ofp_version,
                                                         uint32_t port_no);
  cofgroupmod disable_group_l2_trunk_unfiltered_interface(uint8_t ofp_version,
                                                          uint32_t port_no);

private:
  uint16_t idle_timeout = 0;
  uint16_t max_len = DEFAULT_MAX_LEN;
  static const uint16_t DEFAULT_MAX_LEN = OFPCML_NO_BUFFER;
};

} /* namespace openflow */
} /* namespace rofl */
