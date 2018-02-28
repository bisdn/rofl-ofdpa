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

namespace rofl {
namespace openflow {

class rofl_ofdpa_fm_driver final {
  static const uint16_t DEFAULT_MAX_LEN = OFPCML_NO_BUFFER;

public:
  rofl_ofdpa_fm_driver();
  ~rofl_ofdpa_fm_driver();

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
  GROUP_ID_FUNC_PORT(l2_unfiltered_interface, 11);

  /* OF-DPA Flow-Mods */

  // Overlay Tunnel
  cofflowmod enable_overlay_tunnel(uint8_t ofp_version, uint32_t tunnel_id);
  cofflowmod disable_overlay_tunnel(uint8_t ofp_version, uint32_t tunnel_id);

  // VLAN
  cofflowmod enable_port_pvid_ingress(uint8_t ofp_version, uint32_t port_no,
                                      uint16_t vid);
  cofflowmod disable_port_pvid_ingress(uint8_t ofp_version, uint32_t port_no,
                                       uint16_t vid);

  cofflowmod enable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no,
                                     uint16_t vid);
  cofflowmod disable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no,
                                      uint16_t vid);

  cofflowmod enable_port_vid_allow_all(uint8_t ofp_version, uint32_t port_no);
  cofflowmod disable_port_vid_allow_all(uint8_t ofp_version, uint32_t port_no);

  // Termination MAC
  cofflowmod enable_tmac_ipv4_unicast_mac(uint8_t ofp_version, uint32_t in_port,
                                          uint16_t vid,
                                          const caddress_ll &dmac);
  cofflowmod disable_tmac_ipv4_unicast_mac(uint8_t ofp_version,
                                           uint32_t in_port, uint16_t vid,
                                           const caddress_ll &dmac);

  // Bridging
  cofflowmod add_bridging_dlf_vlan(uint8_t ofp_version, uint16_t vid,
                                   uint32_t group_id);
  cofflowmod remove_bridging_dlf_vlan(uint8_t ofp_version, uint16_t vid);

  cofflowmod add_bridging_unicast_vlan(uint8_t ofp_version, uint32_t port_no,
                                       uint16_t vid, const cmacaddr &mac,
                                       bool permanent = false,
                                       bool filtered = true);

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

  // Unicast Routing
  cofflowmod enable_ipv4_unicast_host(uint8_t ofp_version,
                                      const caddress_in4 &dst, uint32_t group,
                                      const uint16_t max_len = DEFAULT_MAX_LEN);
  cofflowmod disable_ipv4_unicast_host(uint8_t ofp_version,
                                       const caddress_in4 &dst);

  cofflowmod enable_ipv4_unicast_lpm(uint8_t ofp_version,
                                     const caddress_in4 &dst,
                                     const caddress_in4 &mask, uint32_t group);
  cofflowmod disable_ipv4_unicast_lpm(uint8_t ofp_version,
                                      const caddress_in4 &dst,
                                      const caddress_in4 &mask);
  // Policy ACL
  cofflowmod enable_policy_arp(uint8_t ofp_version, bool update = false);

  cofflowmod enable_policy_l2(uint8_t ofp_version, const rofl::caddress_ll &mac,
                              const uint16_t type,
                              const uint16_t max_len = DEFAULT_MAX_LEN);

  cofflowmod
  enable_policy_specific_lacp(uint8_t ofp_version, const caddress_ll &eth_src,
                              const uint16_t timeout_seconds,
                              const uint32_t in_port,
                              const uint16_t max_len = DEFAULT_MAX_LEN);

  cofflowmod disable_policy_l2(uint8_t ofp_version,
                               const rofl::caddress_ll &mac,
                               const uint16_t type);

  cofflowmod disable_policy_specific_lacp(uint8_t ofp_version,
                                          const uint32_t in_port);

  cofflowmod
  enable_policy_broadcast_udp(uint8_t ofp_version, int16_t src_port,
                              int16_t dst_port,
                              const uint16_t max_len = DEFAULT_MAX_LEN);

  cofflowmod enable_policy_vrrp(uint8_t ofp_version,
                                const uint16_t max_len = DEFAULT_MAX_LEN);

  cofflowmod enable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                                       const caddress_ll &dst,
                                       uint32_t group_id, uint64_t cookie);

  cofflowmod disable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                                        const caddress_ll &dst,
                                        uint64_t cookie);

  cofflowmod disable_send_to_l2_rewrite_all(uint8_t ofp_version, uint16_t vid,
                                            uint64_t cookie);

  cofflowmod
  enable_policy_acl_ipv4_vlan(uint8_t ofp_version, const cofmatch &matches,
                              bool clear_actions = false, uint32_t meter_id = 0,
                              uint32_t table_id = 0, uint64_t cookie = 0,
                              const cofactions &apply_actions = cofactions(),
                              const cofactions &write_actions = cofactions());

  cofflowmod disable_policy_acl_ipv4_vlan(uint8_t ofp_version,
                                          const cofmatch &matches,
                                          uint64_t cookie);

  // VLAN Egress
  cofflowmod rewrite_vlan_egress(uint8_t ofp_version, uint32_t backup_port,
                                 uint16_t old_vid, uint16_t new_vid);

  cofflowmod remove_rewritten_vlan_egress(uint8_t ofp_version,
                                          uint32_t backup_port,
                                          uint16_t old_vid, uint16_t new_vid);

  /* OF-DPA Group-Mods */
  cofgroupmod enable_group_l2_interface(uint8_t ofp_version, uint32_t port_no,
                                        uint16_t vid, bool untagged = false);
  cofgroupmod disable_group_l2_interface(uint8_t ofp_version, uint32_t port_no,
                                         uint16_t vid);

  cofgroupmod enable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                   uint32_t port_no);
  cofgroupmod disable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                    uint32_t port_no);

  cofgroupmod
  enable_group_l2_multicast(uint8_t ofp_version, uint16_t vid, uint16_t id,
                            const std::set<uint32_t> &l2_interfaces);

  cofgroupmod enable_group_l2_flood(uint8_t ofp_version, uint16_t vid,
                                    uint16_t id,
                                    const std::set<uint32_t> &l2_interfaces,
                                    bool modify = false);
  cofgroupmod disable_group_l2_flood(uint8_t ofp_version, uint16_t vid,
                                     uint16_t id);

  cofgroupmod enable_group_l2_rewrite(
      uint8_t ofp_version, uint32_t id, uint32_t port_group_id,
      uint16_t vid = 0, const cmacaddr src_mac = cmacaddr{"00:00:00:00:00:00"},
      const cmacaddr dst_mac = cmacaddr{"00:00:00:00:00:00"});

  cofgroupmod disable_group_l2_rewrite(uint8_t ofp_version, uint32_t id);

  cofgroupmod enable_group_l3_interface(uint8_t ofp_version, uint32_t id,
                                        const caddress_ll &src_mac,
                                        uint32_t l2_interface,
                                        const cmacaddr &dst_mac = cmacaddr{
                                            "00:00:00:00:00:00"});

  cofgroupmod disable_group_l3_interface(uint8_t ofp_version, uint32_t id);

  cofgroupmod enable_group_l3_unicast(uint8_t ofp_version, uint32_t id,
                                      const caddress_ll &src_mac,
                                      const cmacaddr &dst_mac,
                                      uint32_t l2_interface);

  cofgroupmod disable_group_l3_unicast(uint8_t ofp_version, uint32_t id);

private:
  const uint16_t default_idle_timeout;
};

} /* namespace openflow */
} /* namespace rofl */
