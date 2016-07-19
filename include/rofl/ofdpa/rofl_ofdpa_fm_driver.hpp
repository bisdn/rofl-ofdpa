/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#pragma once

#include <list>

#include <rofl/common/caddress.h>
#include <rofl/common/crofdpt.h>

#define GROUP_ID_FUNC_PORT_VLAN(name, type_id)                                 \
  inline uint32_t group_id_##name(uint32_t port_no, uint16_t vid) {            \
    /* FIXME check port_no */                                                  \
    return type_id << 28 | (0x0fff & vid) << 16 | (0xffff & port_no);          \
  }                                                                            \
  struct __##name##_useless__

#define GROUP_ID_FUNC_PORT_ID(name, type_id)                                   \
  inline uint32_t group_id_##name(uint16_t id, uint16_t vid) {                 \
    return type_id << 28 | (0x0fff & vid) << 16 | id;                          \
  }                                                                            \
  struct __##name##_useless__

namespace rofl {

class rofl_ofdpa_fm_driver final {
public:
  rofl_ofdpa_fm_driver();
  ~rofl_ofdpa_fm_driver();

  /* OF utils */
  void send_barrier(rofl::crofdpt &dpt);

  GROUP_ID_FUNC_PORT_VLAN(l2_interface, 0);
  GROUP_ID_FUNC_PORT_VLAN(l2_unfiltered_interface, 11);
  GROUP_ID_FUNC_PORT_ID(l2_multicast, 3);
  GROUP_ID_FUNC_PORT_ID(l2_flood, 4);
  GROUP_ID_FUNC_PORT_ID(l3_multicast, 6);

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

  // Briding
  void add_bridging_dlf_vlan(rofl::crofdpt &dpt, uint32_t port_no, uint16_t vid,
                             const rofl::cmacaddr &mac, uint32_t group_id);
  void remove_bridging_dlf_vlan(rofl::crofdpt &dpt, uint32_t port_no,
                                uint16_t vid, const rofl::cmacaddr &mac);

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

  void enable_policy_dhcp(rofl::crofdpt &dpt);

  void enable_policy_vrrp(rofl::crofdpt &dpt);

  // VLAN Egress
  void rewrite_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                           uint16_t old_vid, uint16_t new_vid);

  void remove_rewritten_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                                    uint16_t old_vid, uint16_t new_vid);

  /* OF-DPA Group-Mods */
  uint32_t enable_group_l2_interface(rofl::crofdpt &dpt, uint32_t port_no,
                                     uint16_t vid, bool untagged = false);
  uint32_t disable_group_l2_interface(rofl::crofdpt &dpt, uint32_t port_no,
                                      uint16_t vid, bool untagged);

  uint32_t enable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                uint32_t port_no);
  uint32_t disable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                 uint32_t port_no);

  uint32_t enable_group_l2_multicast(rofl::crofdpt &dpt, uint16_t vid,
                                     uint16_t id,
                                     const std::list<uint32_t> &l2_interfaces);

  uint32_t enable_group_l2_flood(rofl::crofdpt &dpt, uint16_t vid, uint16_t id,
                                 const std::list<uint32_t> &l2_interfaces);

  uint32_t enable_group_l2_rewrite(
      rofl::crofdpt &dpt, uint16_t id, uint32_t port_group_id, uint16_t vid = 0,
      const rofl::cmacaddr src_mac = rofl::cmacaddr{"00:00:00:00:00:00"},
      const rofl::cmacaddr dst_mac = rofl::cmacaddr{"00:00:00:00:00:00"});

private:
  const uint16_t default_idle_timeout;
};

} /* namespace rofl */
