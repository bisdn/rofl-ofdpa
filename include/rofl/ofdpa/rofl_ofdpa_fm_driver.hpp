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

  void enable_port_pvid_ingress(rofl::crofdpt &dpt,
                                const std::string &port_name, uint16_t vid);
  void disable_port_pvid_ingress(rofl::crofdpt &dpt,
                                 const std::string &port_name, uint16_t vid);

  void enable_port_vid_ingress(rofl::crofdpt &dpt, const std::string &port_name,
                               uint16_t vid);
  void disable_port_vid_ingress(rofl::crofdpt &dpt,
                                const std::string &port_name, uint16_t vid);

  void enable_port_vid_allow_all(rofl::crofdpt &dpt,
                                 const std::string &port_name);
  void disable_port_vid_allow_all(rofl::crofdpt &dpt,
                                  const std::string &port_name);

  uint32_t enable_port_vid_egress(rofl::crofdpt &dpt,
                                  const std::string &port_name, uint16_t vid,
                                  bool untagged = false);
  uint32_t disable_port_vid_egress(rofl::crofdpt &dpt,
                                   const std::string &port_name, uint16_t vid,
                                   bool untagged);

  uint32_t enable_port_unfiltered_egress(rofl::crofdpt &dpt,
                                         const std::string &port_name);
  uint32_t disable_port_unfiltered_egress(rofl::crofdpt &dpt,
                                          const std::string &port_name);

  uint32_t enable_group_l2_multicast(rofl::crofdpt &dpt, uint16_t vid,
                                     uint16_t id,
                                     const std::list<uint32_t> &l2_interfaces,
                                     bool update = false);

  void enable_policy_arp(rofl::crofdpt &dpt, uint16_t vid, uint32_t group_id,
                         bool update = false);

  void enable_policy_lldp(rofl::crofdpt &dpt);

  void enable_policy_dhcp(rofl::crofdpt &dpt);

  void enable_policy_vrrp(rofl::crofdpt &dpt);

  void add_bridging_unicast_vlan(rofl::crofdpt &dpt, const rofl::cmacaddr &mac,
                                 uint16_t vid, uint32_t port_no,
                                 bool permanent = false, bool filtered = true);

  void remove_bridging_unicast_vlan(rofl::crofdpt &dpt,
                                    const rofl::cmacaddr &mac, uint16_t vid,
                                    uint32_t port_no);
  void remove_bridging_unicast_vlan_all(rofl::crofdpt &dpt,
                                        const std::string &port_name,
                                        uint16_t vid);

  void rewrite_vlan_egress(rofl::crofdpt &dpt, uint16_t old_vid,
                           uint16_t new_vid, uint32_t backup_port);

  void remove_rewritten_vlan_egress(rofl::crofdpt &dpt, uint16_t old_vid,
                                    uint16_t new_vid, uint32_t backup_port);

private:
  const uint16_t default_idle_timeout;
};

} /* namespace rofl */

#endif /* ROFL_OFDPA_FM_DRIVER_HPP_ */
