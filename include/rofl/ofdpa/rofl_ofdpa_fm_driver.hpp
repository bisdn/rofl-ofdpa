/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <set>

#include <rofl/common/caddress.h>
#include <rofl/common/openflow/cofflowmod.h>
#include <rofl/common/openflow/cofgroupmod.h>

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

class rofl_ofdpa_fm_driver final {
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

  // VLAN
  rofl::openflow::cofflowmod
  enable_port_pvid_ingress(uint8_t ofp_version, uint32_t port_no, uint16_t vid);
  rofl::openflow::cofflowmod disable_port_pvid_ingress(uint8_t ofp_version,
                                                       uint32_t port_no,
                                                       uint16_t vid);

  rofl::openflow::cofflowmod
  enable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no, uint16_t vid);
  rofl::openflow::cofflowmod
  disable_port_vid_ingress(uint8_t ofp_version, uint32_t port_no, uint16_t vid);

  rofl::openflow::cofflowmod enable_port_vid_allow_all(uint8_t ofp_version,
                                                       uint32_t port_no);
  rofl::openflow::cofflowmod disable_port_vid_allow_all(uint8_t ofp_version,
                                                        uint32_t port_no);

  // Termination MAC
  rofl::openflow::cofflowmod
  enable_tmac_ipv4_unicast_mac(uint8_t ofp_version, uint32_t in_port,
                               uint16_t vid, const rofl::caddress_ll &dmac);
  rofl::openflow::cofflowmod
  disable_tmac_ipv4_unicast_mac(uint8_t ofp_version, uint32_t in_port,
                                uint16_t vid, const rofl::caddress_ll &dmac);

  // Unicast Routing
  rofl::openflow::cofflowmod
  enable_ipv4_unicast_host(uint8_t ofp_version, const rofl::caddress_in4 &dst,
                           uint32_t group);
  rofl::openflow::cofflowmod
  disable_ipv4_unicast_host(uint8_t ofp_version, const rofl::caddress_in4 &dst);

  rofl::openflow::cofflowmod
  enable_ipv4_unicast_lpm(uint8_t ofp_version, const rofl::caddress_in4 &dst,
                          const rofl::caddress_in4 &mask, uint32_t group);
  rofl::openflow::cofflowmod
  disable_ipv4_unicast_lpm(uint8_t ofp_version, const rofl::caddress_in4 &dst,
                           const rofl::caddress_in4 &mask);
  // Bridging
  rofl::openflow::cofflowmod
  add_bridging_dlf_vlan(uint8_t ofp_version, uint16_t vid, uint32_t group_id);
  rofl::openflow::cofflowmod remove_bridging_dlf_vlan(uint8_t ofp_version,
                                                      uint16_t vid);

  rofl::openflow::cofflowmod
  add_bridging_unicast_vlan(uint8_t ofp_version, uint32_t port_no, uint16_t vid,
                            const rofl::cmacaddr &mac, bool permanent = false,
                            bool filtered = true);

  rofl::openflow::cofflowmod
  remove_bridging_unicast_vlan(uint8_t ofp_version, uint32_t port_no,
                               uint16_t vid, const rofl::cmacaddr &mac);
  rofl::openflow::cofflowmod
  remove_bridging_unicast_vlan_all(uint8_t ofp_version, uint32_t port_no,
                                   uint16_t vid);

  // Policy ACL
  rofl::openflow::cofflowmod enable_policy_arp(uint8_t ofp_version,
                                               bool update = false);

  rofl::openflow::cofflowmod enable_policy_lldp(uint8_t ofp_version);

  rofl::openflow::cofflowmod enable_policy_lacp(uint8_t ofp_version);

  rofl::openflow::cofflowmod enable_policy_specific_lacp(
      uint8_t ofp_version, const rofl::caddress_ll &eth_src,
      const uint16_t timeout_seconds, const uint32_t in_port);

  rofl::openflow::cofflowmod disable_policy_lacp(uint8_t ofp_version);

  rofl::openflow::cofflowmod
  disable_policy_specific_lacp(uint8_t ofp_version, const uint32_t in_port);

  rofl::openflow::cofflowmod enable_policy_broadcast_udp(uint8_t ofp_version,
                                                         int16_t src_port,
                                                         int16_t dst_port);

  rofl::openflow::cofflowmod enable_policy_vrrp(uint8_t ofp_version);

  rofl::openflow::cofflowmod
  enable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                            const rofl::caddress_ll &dst, uint32_t group_id,
                            uint64_t cookie);

  rofl::openflow::cofflowmod
  disable_send_to_l2_rewrite(uint8_t ofp_version, uint16_t vid,
                             const rofl::caddress_ll &dst, uint64_t cookie);

  rofl::openflow::cofflowmod disable_send_to_l2_rewrite_all(uint8_t ofp_version,
                                                            uint16_t vid,
                                                            uint64_t cookie);

  rofl::openflow::cofflowmod
  enable_policy_acl_ipv4_vlan(uint8_t ofp_version,
                              const rofl::openflow::cofmatch &matches,
                              bool clear_actions = false, uint32_t meter_id = 0,
                              uint32_t table_id = 0, uint64_t cookie = 0,
                              const rofl::openflow::cofactions &apply_actions =
                                  rofl::openflow::cofactions(),
                              const rofl::openflow::cofactions &write_actions =
                                  rofl::openflow::cofactions());

  rofl::openflow::cofflowmod
  disable_policy_acl_ipv4_vlan(uint8_t ofp_version,
                               const rofl::openflow::cofmatch &matches,
                               uint64_t cookie);

  // VLAN Egress
  rofl::openflow::cofflowmod rewrite_vlan_egress(uint8_t ofp_version,
                                                 uint32_t backup_port,
                                                 uint16_t old_vid,
                                                 uint16_t new_vid);

  rofl::openflow::cofflowmod remove_rewritten_vlan_egress(uint8_t ofp_version,
                                                          uint32_t backup_port,
                                                          uint16_t old_vid,
                                                          uint16_t new_vid);

  /* OF-DPA Group-Mods */
  rofl::openflow::cofgroupmod enable_group_l2_interface(uint8_t ofp_version,
                                                        uint32_t port_no,
                                                        uint16_t vid,
                                                        bool untagged = false);
  rofl::openflow::cofgroupmod disable_group_l2_interface(uint8_t ofp_version,
                                                         uint32_t port_no,
                                                         uint16_t vid);

  rofl::openflow::cofgroupmod
  enable_group_l2_unfiltered_interface(uint8_t ofp_version, uint32_t port_no);
  rofl::openflow::cofgroupmod
  disable_group_l2_unfiltered_interface(uint8_t ofp_version, uint32_t port_no);

  rofl::openflow::cofgroupmod
  enable_group_l2_multicast(uint8_t ofp_version, uint16_t vid, uint16_t id,
                            const std::set<uint32_t> &l2_interfaces);

  rofl::openflow::cofgroupmod
  enable_group_l2_flood(uint8_t ofp_version, uint16_t vid, uint16_t id,
                        const std::set<uint32_t> &l2_interfaces);
  rofl::openflow::cofgroupmod disable_group_l2_flood(uint8_t ofp_version,
                                                     uint16_t vid, uint16_t id);

  rofl::openflow::cofgroupmod enable_group_l2_rewrite(
      uint8_t ofp_version, uint32_t id, uint32_t port_group_id,
      uint16_t vid = 0,
      const rofl::cmacaddr src_mac = rofl::cmacaddr{"00:00:00:00:00:00"},
      const rofl::cmacaddr dst_mac = rofl::cmacaddr{"00:00:00:00:00:00"});

  rofl::openflow::cofgroupmod disable_group_l2_rewrite(uint8_t ofp_version,
                                                       uint32_t id);

  rofl::openflow::cofgroupmod enable_group_l3_interface(
      uint8_t ofp_version, uint32_t id, const rofl::caddress_ll &src_mac,
      uint32_t l2_interface,
      const rofl::cmacaddr &dst_mac = rofl::cmacaddr{"00:00:00:00:00:00"});

  rofl::openflow::cofgroupmod disable_group_l3_interface(uint8_t ofp_version,
                                                         uint32_t id);

  rofl::openflow::cofgroupmod
  enable_group_l3_unicast(uint8_t ofp_version, uint32_t id,
                          const rofl::caddress_ll &src_mac,
                          const rofl::cmacaddr &dst_mac, uint32_t l2_interface);

  rofl::openflow::cofgroupmod disable_group_l3_unicast(uint8_t ofp_version,
                                                       uint32_t id);

private:
  const uint16_t default_idle_timeout;
};

} /* namespace rofl */
