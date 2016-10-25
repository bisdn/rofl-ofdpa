/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <set>

#include <rofl/common/caddress.h>
#include <rofl/common/crofdpt.h>

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
    return type_id << 28 | (0xffffff & id);                                    \
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
  void enable_port_pvid_ingress(rofl::crofdpt &dpt, uint32_t port_no,
                                uint16_t vid);
  void disable_port_pvid_ingress(rofl::crofdpt &dpt, uint32_t port_no,
                                 uint16_t vid);

  void enable_port_vid_ingress(rofl::crofdpt &dpt, uint32_t port_no,
                               uint16_t vid);
  void disable_port_vid_ingress(rofl::crofdpt &dpt, uint32_t port_no,
                                uint16_t vid);

  void enable_port_vid_allow_all(rofl::crofdpt &dpt, uint32_t port_no);
  void disable_port_vid_allow_all(rofl::crofdpt &dpt, uint32_t port_no);

  // Termination MAC
  void enable_tmac_ipv4_unicast_mac(rofl::crofdpt &dpt, uint32_t in_port,
                                    rofl::caddress_ll &dmac, uint16_t vid);
  void disable_tmac_ipv4_unicast_mac(rofl::crofdpt &dpt, uint32_t in_port,
                                     rofl::caddress_ll &dmac, uint16_t vid);

  // Unicast Routing
  void enable_ipv4_unicast_host(rofl::crofdpt &dpt, rofl::caddress_in4 &dst,
                                uint32_t group, bool send_to_ctl = false);
  void disable_ipv4_unicast_host(rofl::crofdpt &dpt, rofl::caddress_in4 &dst,
                                 uint32_t group);

  void enable_ipv4_unicast_lpm(rofl::crofdpt &dpt,
                               const rofl::caddress_in4 &dst,
                               const rofl::caddress_in4 &mask, uint32_t group);
  void disable_ipv4_unicast_lpm(rofl::crofdpt &dpt,
                                const rofl::caddress_in4 &dst,
                                const rofl::caddress_in4 &mask, uint32_t group);
  // Briding
  void add_bridging_dlf_vlan(rofl::crofdpt &dpt, uint16_t vid,
                             uint32_t group_id);
  void remove_bridging_dlf_vlan(rofl::crofdpt &dpt, uint16_t vid);

  void add_bridging_unicast_vlan(rofl::crofdpt &dpt, uint32_t port_no,
                                 uint16_t vid, const rofl::cmacaddr &mac,
                                 bool permanent = false, bool filtered = true);

  void remove_bridging_unicast_vlan(rofl::crofdpt &dpt, uint32_t port_no,
                                    uint16_t vid, const rofl::cmacaddr &mac);
  void remove_bridging_unicast_vlan_all(rofl::crofdpt &dpt, uint32_t port_no,
                                        uint16_t vid);

  // Policy ACL
  void enable_policy_arp(rofl::crofdpt &dpt, uint16_t vid, uint32_t group_id,
                         bool update = false);

  void enable_policy_lldp(rofl::crofdpt &dpt);

  void enable_policy_lacp(rofl::crofdpt &dpt);

  void enable_policy_specific_lacp(rofl::crofdpt &dpt,
                                   const rofl::caddress_ll &eth_src,
                                   uint8_t timeout_seconds,
                                   const uint32_t in_port);

  void disable_policy_lacp(rofl::crofdpt &dpt);

  void disable_policy_specific_lacp(rofl::crofdpt &dpt, const uint32_t in_port);

  void enable_policy_dhcp(rofl::crofdpt &dpt);

  void enable_policy_vrrp(rofl::crofdpt &dpt);

  void enable_send_to_l2_rewrite(rofl::crofdpt &dpt, uint16_t vid,
                                 const rofl::caddress_ll &dst,
                                 uint32_t group_id);

  void disable_send_to_l2_rewrite(rofl::crofdpt &dpt, uint16_t vid,
                                  const rofl::caddress_ll &dst);

  void enable_policy_acl_ipv4_vlan(
      rofl::crofdpt &dpt, const rofl::openflow::cofmatch &matches,
      bool clear_actions = false, uint32_t meter_id = 0, uint32_t table_id = 0,
      const rofl::openflow::cofactions &apply_actions =
          rofl::openflow::cofactions(),
      const rofl::openflow::cofactions &write_actions =
          rofl::openflow::cofactions());

  void disable_policy_acl_ipv4_vlan(rofl::crofdpt &dpt,
                                    const rofl::openflow::cofmatch &matches);

  // VLAN Egress
  void rewrite_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                           uint16_t old_vid, uint16_t new_vid);

  void remove_rewritten_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                                    uint16_t old_vid, uint16_t new_vid);

  /* OF-DPA Group-Mods */
  uint32_t enable_group_l2_interface(rofl::crofdpt &dpt, uint32_t port_no,
                                     uint16_t vid, bool untagged = false);
  uint32_t disable_group_l2_interface(rofl::crofdpt &dpt, uint32_t port_no,
                                      uint16_t vid);

  uint32_t enable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                uint32_t port_no);
  uint32_t disable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                 uint32_t port_no);

  uint32_t enable_group_l2_multicast(rofl::crofdpt &dpt, uint16_t vid,
                                     uint16_t id,
                                     const std::set<uint32_t> &l2_interfaces);

  uint32_t enable_group_l2_flood(rofl::crofdpt &dpt, uint16_t vid, uint16_t id,
                                 const std::set<uint32_t> &l2_interfaces);
  uint32_t disable_group_l2_flood(rofl::crofdpt &dpt, uint16_t vid,
                                  uint16_t id);

  uint32_t enable_group_l2_rewrite(
      rofl::crofdpt &dpt, uint32_t id, uint32_t port_group_id, uint16_t vid = 0,
      const rofl::cmacaddr src_mac = rofl::cmacaddr{"00:00:00:00:00:00"},
      const rofl::cmacaddr dst_mac = rofl::cmacaddr{"00:00:00:00:00:00"});

  uint32_t disable_group_l2_rewrite(rofl::crofdpt &dpt, uint32_t id);

  uint32_t enable_group_l3_interface(
      rofl::crofdpt &dpt, uint32_t id, rofl::caddress_ll &src_mac,
      uint32_t l2_interface,
      const rofl::cmacaddr &dst_mac = rofl::cmacaddr{"00:00:00:00:00:00"});

  uint32_t disable_group_l3_interface(rofl::crofdpt &dpt, uint32_t id);

  uint32_t enable_group_l3_unicast(rofl::crofdpt &dpt, uint32_t id,
                                   rofl::caddress_ll &src_mac,
                                   const rofl::cmacaddr &dst_mac,
                                   uint32_t l2_interface);

  uint32_t disable_group_l3_unicast(rofl::crofdpt &dpt, uint32_t id);

private:
  const uint16_t default_idle_timeout;
};

} /* namespace rofl */
