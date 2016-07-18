/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef ROFL_OFDPA_FM_DRIVER_HPP_
#define ROFL_OFDPA_FM_DRIVER_HPP_

#include <list>

#include <rofl/common/crofdpt.h>
#include <rofl/common/caddress.h>

namespace rofl {

class rofl_ofdpa_fm_driver final {
public:
  rofl_ofdpa_fm_driver();
  ~rofl_ofdpa_fm_driver();

  void send_barrier(rofl::crofdpt &dpt);

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
                                     const std::list<uint32_t> &l2_interfaces,
                                     bool update = false);

  uint32_t enable_group_l2_flood(rofl::crofdpt &dpt, uint16_t vid, uint16_t id,
                                 const std::list<uint32_t> &l2_interfaces,
                                 bool update = false);

  void enable_policy_arp(rofl::crofdpt &dpt, uint16_t vid, uint32_t group_id,
                         bool update = false);

  void enable_policy_lldp(rofl::crofdpt &dpt);

  void enable_policy_dhcp(rofl::crofdpt &dpt);

  void enable_policy_vrrp(rofl::crofdpt &dpt);

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

  void rewrite_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                           uint16_t old_vid, uint16_t new_vid);

  void remove_rewritten_vlan_egress(rofl::crofdpt &dpt, uint32_t backup_port,
                                    uint16_t old_vid, uint16_t new_vid);

private:
  const uint16_t default_idle_timeout;
};

} /* namespace rofl */

#endif /* ROFL_OFDPA_FM_DRIVER_HPP_ */
