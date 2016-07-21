/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ofdpa_datatypes.h"

#include <rofl/common/crofdpt.h>
#include <rofl/common/openflow/cofflowmod.h>
#include <rofl/common/openflow/coxmatch.h>
#include <rofl/common/openflow/openflow_common.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <rofl/ofdpa/rofl_ofdpa_fm_driver.hpp>

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP 112
#endif

#ifdef DEBUG
#define DEBUG_LOG(x) std::cerr << __PRETTY_FUNCTION__ << ": " << x << std::endl
#else
#define DEBUG_LOG(x)
#endif

namespace rofl {

namespace ofdpa {

#define HAS_MASK_FLAG (1 << 8)

/* OXM Flow match field types for OpenFlow experimenter class. */
enum oxm_tlv_match_fields {
  OXM_TLV_EXPR_VRF =
      (rofl::openflow::OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_VRF << 9) | 2,
  OXM_TLV_EXPR_VRF_MASK = (rofl::openflow::OFPXMC_EXPERIMENTER << 16) |
                          (OFDPA_OXM_VRF << 9) | 4 | HAS_MASK_FLAG,
  OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION =
      (rofl::openflow::OFPXMC_EXPERIMENTER << 16) |
      (OFDPA_OXM_ALLOW_VLAN_TRANSLATION << 9) | 5,
  OXM_TLV_EXPR_ACTSET_OUTPUT = (rofl::openflow::OFPXMC_EXPERIMENTER << 16) |
                               (OFDPA_OXM_ACTSET_OUTPUT << 9) | 8,
};

class coxmatch_ofb_vrf : public rofl::openflow::coxmatch_exp {
public:
  coxmatch_ofb_vrf(uint16_t vrf)
      : coxmatch_exp(ofdpa::OXM_TLV_EXPR_VRF, EXP_ID_BCM, vrf) {}

  coxmatch_ofb_vrf(uint16_t vrf, uint16_t mask)
      : coxmatch_exp(ofdpa::OXM_TLV_EXPR_VRF_MASK, EXP_ID_BCM, vrf, mask) {}

  coxmatch_ofb_vrf(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_vrf() {}

  friend std::ostream &operator<<(std::ostream &os,
                                  const coxmatch_ofb_vrf &oxm) {
    os << dynamic_cast<const coxmatch &>(oxm);
    os << "  <coxmatch_ofb_vlan_vid >" << std::endl;
    os << "    <vlan-vid: 0x" << std::hex << (int)oxm.get_u16value() << "/0x"
       << (int)oxm.get_u16mask() << std::dec << " >" << std::endl;
    return os;
  }
};

class coxmatch_ofb_allow_vlan_translation
    : public rofl::openflow::coxmatch_exp {
public:
  coxmatch_ofb_allow_vlan_translation(uint8_t val)
      : coxmatch_exp(ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION, EXP_ID_BCM,
                     val) {}

  coxmatch_ofb_allow_vlan_translation(const coxmatch_exp &oxm)
      : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_allow_vlan_translation() {}

  friend std::ostream &
  operator<<(std::ostream &os, const coxmatch_ofb_allow_vlan_translation &oxm) {
    os << dynamic_cast<const coxmatch &>(oxm);
    os << "  <coxmatch_ofb_allow_vlan_translation >" << std::endl;
    os << "    <value: 0x" << std::hex << (int)oxm.get_u8value() << std::dec
       << " >" << std::endl;
    return os;
  }
};

class coxmatch_ofb_actset_output : public rofl::openflow::coxmatch_exp {

  struct broadcom_t {
    uint32_t portno;
  } __attribute__((packed));

public:
  coxmatch_ofb_actset_output(uint32_t port)
      : coxmatch_exp(ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT, ONF_EXP_ID_ONF, port) {}

  coxmatch_ofb_actset_output(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_actset_output() {}

  friend std::ostream &operator<<(std::ostream &os,
                                  const coxmatch_ofb_actset_output &oxm) {
    os << dynamic_cast<const coxmatch &>(oxm);
    os << "<coxmatch_ofb_actset_output >" << std::endl;
    os << "    <port: 0x" << std::hex << (int)oxm.get_u32value() << std::dec
       << " >" << std::endl;
    return os;
  }
};

}; // end of namespace ofdpa

static inline uint64_t gen_flow_mod_type_cookie(uint64_t val) {
  return (val << 8 * 7);
}

rofl_ofdpa_fm_driver::rofl_ofdpa_fm_driver()
    : default_idle_timeout(30) // TODO idle timeout should be configurable
{}

rofl_ofdpa_fm_driver::~rofl_ofdpa_fm_driver() {}

void rofl_ofdpa_fm_driver::send_barrier(rofl::crofdpt &dpt) {
  dpt.send_barrier_request(rofl::cauxid(0));
}

void rofl_ofdpa_fm_driver::enable_port_pvid_ingress(rofl::crofdpt &dpt,
                                                    uint32_t port_no,
                                                    uint16_t vid) {
  enable_port_vid_ingress(dpt, port_no, vid);

  // check params
  assert(vid < 0x1000);
  rofl::openflow::cofflowmod fm(dpt.get_version());

  fm.set_command(rofl::openflow::OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_ASSIGNMENT) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(0);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_set_field(rofl::cindex(0))
      .set_oxm(rofl::openflow::coxmatch_ofb_vlan_vid(
          rofl::openflow::OFPVID_PRESENT | vid));

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::disable_port_pvid_ingress(rofl::crofdpt &dpt,
                                                     uint32_t port_no,
                                                     uint16_t vid) {

  // check params
  assert(vid < 0x1000);
  rofl::openflow::cofflowmod fm(dpt.get_version());

  fm.set_command(rofl::openflow::OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_ASSIGNMENT) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(0);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);

  disable_port_vid_ingress(dpt, port_no, vid);
}

void rofl_ofdpa_fm_driver::enable_port_vid_ingress(rofl::crofdpt &dpt,
                                                   uint32_t port_no,
                                                   uint16_t vid) {
  assert(vid < 0x1000);
  rofl::openflow::cofflowmod fm(dpt.get_version());

  // TODO check what happens if this is added two times?
  fm.set_command(rofl::openflow::OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_FILTERING) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(rofl::openflow::OFPVID_PRESENT | vid);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::disable_port_vid_ingress(rofl::crofdpt &dpt,
                                                    uint32_t port_no,
                                                    uint16_t vid) {
  assert(vid < 0x1000);
  rofl::openflow::cofflowmod fm(dpt.get_version());

  fm.set_command(rofl::openflow::OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_FILTERING) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(rofl::openflow::OFPVID_PRESENT | vid);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::enable_port_vid_allow_all(rofl::crofdpt &dpt,
                                                     uint32_t port_no) {
  rofl::openflow::cofflowmod fm(dpt.get_version());

  fm.set_command(rofl::openflow::OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(7);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_ALLOW_ALL) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(rofl::openflow::OFPVID_PRESENT,
                              rofl::openflow::OFPVID_PRESENT);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::disable_port_vid_allow_all(rofl::crofdpt &dpt,
                                                      uint32_t port_no) {
  // XXX implement!!
  DEBUG_LOG(": not implemented");
}

uint32_t rofl_ofdpa_fm_driver::enable_group_l2_interface(rofl::crofdpt &dpt,
                                                         uint32_t port_no,
                                                         uint16_t vid,
                                                         bool untagged) {
  assert(vid < 0x1000);
  uint32_t group_id = group_id_l2_interface(port_no, vid);
  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_ADD);
  gm.set_type(rofl::openflow::OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  rofl::cindex i(0);
  if (untagged) {
    gm.set_buckets().add_bucket(0).set_actions().add_action_pop_vlan(i++);
  }

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(ofdpa::coxmatch_ofb_allow_vlan_translation(0));

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_output(i++)
      .set_port_no(port_no);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t rofl_ofdpa_fm_driver::disable_group_l2_interface(rofl::crofdpt &dpt,
                                                          uint32_t port_no,
                                                          uint16_t vid,
                                                          bool untagged) {
  assert(vid < 0x1000);
  uint32_t group_id = group_id_l2_interface(port_no, vid);
  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_DELETE);
  gm.set_type(rofl::openflow::OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t
rofl_ofdpa_fm_driver::enable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                           uint32_t port_no) {
  uint32_t group_id = group_id_l2_unfiltered_interface(port_no, 0);
  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_ADD);
  gm.set_type(rofl::openflow::OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  rofl::cindex i(0);

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(ofdpa::coxmatch_ofb_allow_vlan_translation(1));

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_output(i++)
      .set_port_no(port_no);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t
rofl_ofdpa_fm_driver::disable_group_l2_unfiltered_interface(rofl::crofdpt &dpt,
                                                            uint32_t port_no) {
  uint32_t group_id = group_id_l2_unfiltered_interface(port_no, 0);
  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_DELETE);
  gm.set_type(rofl::openflow::OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t rofl_ofdpa_fm_driver::enable_group_l2_rewrite(
    rofl::crofdpt &dpt, uint32_t id, uint32_t port_group_id, uint16_t vid,
    const rofl::cmacaddr src_mac, const rofl::cmacaddr dst_mac) {

  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_rewrite(id);

  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_ADD);
  gm.set_type(rofl::openflow::OFPGT_ALL);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  rofl::openflow::cofactions &action_set =
      gm.set_buckets().add_bucket(bucket_id).set_actions();

  if (vid != 0) {
    action_set
        .set_action_set_vlan_vid(
            rofl::cindex(rofl::openflow::OFPAT_SET_VLAN_VID))
        .set_vlan_vid(vid);
  }

  if (src_mac.str() != "00:00:00:00:00:00") {
    action_set
        .set_action_set_dl_src(rofl::cindex(rofl::openflow::OFPAT_SET_DL_SRC))
        .set_dl_src(src_mac);
  }

  if (dst_mac.str() != "00:00:00:00:00:00") {
    action_set
        .set_action_set_dl_dst(rofl::cindex(rofl::openflow::OFPAT_SET_DL_DST))
        .set_dl_dst(dst_mac);
  }

  action_set.set_action_group(rofl::cindex(0)).set_group_id(port_group_id);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t rofl_ofdpa_fm_driver::enable_group_l2_multicast(
    rofl::crofdpt &dpt, uint16_t vid, uint16_t id,
    const std::set<uint32_t> &l2_interfaces) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_multicast(id, vid);

  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_ADD);
  gm.set_type(rofl::openflow::OFPGT_ALL);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  for (const uint32_t &i : l2_interfaces) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_group(rofl::cindex(0))
        .set_group_id(i);
  }

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t rofl_ofdpa_fm_driver::enable_group_l2_flood(
    rofl::crofdpt &dpt, uint16_t vid, uint16_t id,
    const std::set<uint32_t> &l2_interfaces) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_flood(id, vid);

  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_ADD);
  gm.set_type(rofl::openflow::OFPGT_ALL);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  for (const uint32_t &i : l2_interfaces) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_group(rofl::cindex(0))
        .set_group_id(i);
  }

  DEBUG_LOG(": send group-mod:" << std::endl << gm);

  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

uint32_t rofl_ofdpa_fm_driver::disable_group_l2_flood(rofl::crofdpt &dpt,
                                                      uint16_t vid,
                                                      uint16_t id) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_flood(id, vid);
  rofl::openflow::cofgroupmod gm(dpt.get_version());

  gm.set_command(rofl::openflow::OFPGC_DELETE);
  gm.set_type(rofl::openflow::OFPGT_ALL);
  gm.set_group_id(group_id);

  DEBUG_LOG(": send group-mod:" << std::endl << gm);
  dpt.send_group_mod_message(rofl::cauxid(0), gm);

  return group_id;
}

void rofl_ofdpa_fm_driver::enable_policy_arp(rofl::crofdpt &dpt, uint16_t vid,
                                             uint32_t group_id, bool update) {
  assert(vid < 0x1000);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(update ? rofl::openflow::OFPFC_MODIFY
                        : rofl::openflow::OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_ARP);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(rofl::cindex(0))
      .set_port_no(rofl::openflow::OFPP_CONTROLLER);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::enable_policy_lldp(rofl::crofdpt &dpt) {
  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(rofl::openflow::OFPFC_ADD);

  fm.set_match().set_eth_dst(rofl::cmacaddr("01:80:c2:00:00:00"));

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(rofl::cindex(0))
      .set_port_no(rofl::openflow::OFPP_CONTROLLER);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::enable_policy_dhcp(rofl::crofdpt &dpt) {
  using rofl::caddress_in4;

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(rofl::openflow::OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IP);

  fm.set_match().set_ipv4_dst(caddress_in4(std::string("255.255.255.255")));
  fm.set_match().set_ip_proto(IPPROTO_UDP);
  fm.set_match().set_udp_src(68); // bootpc
  fm.set_match().set_udp_dst(67); // bootps

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(rofl::cindex(0))
      .set_port_no(rofl::openflow::OFPP_CONTROLLER);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);

  fm.set_match().set_udp_src(67); // bootps
  fm.set_match().set_udp_dst(68); // bootpc

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::enable_policy_vrrp(rofl::crofdpt &dpt) {
  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(rofl::openflow::OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IP);

  fm.set_match().set_ipv4_dst(caddress_in4(std::string("224.0.0.18")));
  fm.set_match().set_ip_proto(IPPROTO_VRRP);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(rofl::cindex(0))
      .set_port_no(rofl::openflow::OFPP_CONTROLLER);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::add_bridging_dlf_vlan(rofl::crofdpt &dpt,
                                                 uint32_t port_no, uint16_t vid,
                                                 uint32_t group_id) {
  assert(vid < 0x1000);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_VLAN) |
                port_no);

  fm.set_command(rofl::openflow::OFPFC_ADD);

  fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);

  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(rofl::cindex(0))
      .set_group_id(group_id);
  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::remove_bridging_dlf_vlan(rofl::crofdpt &dpt,
                                                    uint32_t port_no,
                                                    uint16_t vid) {
  assert(vid < 0x1000);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_VLAN) |
                port_no);

  // TODO do this strict?
  fm.set_command(rofl::openflow::OFPFC_DELETE);

  fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::add_bridging_unicast_vlan(
    rofl::crofdpt &dpt, uint32_t port_no, uint16_t vid,
    const rofl::cmacaddr &mac, bool permanent, bool filtered) {
  assert(vid < 0x1000);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(permanent ? 0 : default_idle_timeout);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);

  if (not permanent) {
    fm.set_flags(rofl::openflow::OFPFF_SEND_FLOW_REM);
  }

  fm.set_command(rofl::openflow::OFPFC_ADD);

  // FIXME do not allow multicast mac here?
  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);

  uint32_t group_id;
  if (filtered) {
    group_id = group_id_l2_interface(port_no, vid);
  } else {
    group_id = group_id_l2_unfiltered_interface(port_no, 0);
  }
  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(rofl::cindex(0))
      .set_group_id(group_id);
  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::remove_bridging_unicast_vlan(
    rofl::crofdpt &dpt, uint32_t port_no, uint16_t vid,
    const rofl::cmacaddr &mac) {
  assert(vid < 0x1000);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);

  // TODO do this strict?
  fm.set_command(rofl::openflow::OFPFC_DELETE);

  // FIXME do not allow multicast mac here?
  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | rofl::openflow::OFPVID_PRESENT);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::remove_bridging_unicast_vlan_all(rofl::crofdpt &dpt,
                                                            uint32_t port_no,
                                                            uint16_t vid) {
  using rofl::openflow::OFPVID_PRESENT;
  assert(vid < 0x1000 || (uint16_t)-1 == vid);

  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);
  fm.set_cookie_mask(-1);

  // TODO do this strict?
  fm.set_command(rofl::openflow::OFPFC_DELETE);
  if ((uint16_t)-1 != vid) {
    fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  }

  DEBUG_LOG(": send flow-mod: " << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::rewrite_vlan_egress(rofl::crofdpt &dpt,
                                               uint32_t backup_port,
                                               uint16_t old_vid,
                                               uint16_t new_vid) {
  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(
          OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG_OR_SINGLE_TO_DOUBLE) |
      0);

  fm.set_command(rofl::openflow::OFPFC_ADD);

  ofdpa::coxmatch_ofb_actset_output exp_match(backup_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(rofl::openflow::OFPVID_PRESENT | old_vid);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_set_field(rofl::cindex(0))
      .set_oxm(rofl::openflow::coxmatch_ofb_vlan_vid(
          rofl::openflow::OFPVID_PRESENT | new_vid));

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

void rofl_ofdpa_fm_driver::remove_rewritten_vlan_egress(rofl::crofdpt &dpt,
                                                        uint32_t backup_port,
                                                        uint16_t old_vid,
                                                        uint16_t new_vid) {
  rofl::openflow::cofflowmod fm(dpt.get_version());
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);

  fm.set_idle_timeout(0);
  fm.set_hard_timeout(0);
  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(
          OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG_OR_SINGLE_TO_DOUBLE) |
      0);

  fm.set_command(rofl::openflow::OFPFC_DELETE);

  ofdpa::coxmatch_ofb_actset_output exp_match(backup_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(rofl::openflow::OFPVID_PRESENT | old_vid);

  DEBUG_LOG(": send flow-mod:" << std::endl << fm);

  dpt.send_flow_mod_message(rofl::cauxid(0), fm);
}

} /* namespace rofl */
