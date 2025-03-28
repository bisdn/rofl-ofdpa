/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ofdpa_datatypes.h"

#include <rofl/common/openflow/coxmatch.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <rofl/ofdpa/rofl_ofdpa_fm_driver.hpp>

#include <rofl/common/openflow/experimental/actions/ext320_actions.h>
#include <rofl/common/openflow/extensions/matches/ext244_matches.h>

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP 112
#endif

#ifdef DEBUG
#define DEBUG_LOG(x) std::cerr << __PRETTY_FUNCTION__ << ": " << x << std::endl
#else
#define DEBUG_LOG(x)
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef OXM_TLV_CLASS_TYPE
#define OXM_TLV_CLASS_TYPE(x) ((x) & (0xfffffe00))
#endif

namespace rofl {
namespace openflow {

namespace ofdpa {

#define HAS_MASK_FLAG (1 << 8)

// OXM Flow match field types for OpenFlow experimenter class.
// Original values can be found in ofagent's of_oxm_wire_object_id_get(), see
// https://github.com/bisdn/of-dpa/blob/master/src/ofagent/indigo/submodules/loxigen-artifacts/loci/src/class05.c#L34
// Note that while the parser understands OF_OXM_BSN_* matches, the OF-DPA
// adapter does not support them.
enum oxm_tlv_match_fields {
  OXM_TLV_EXPR_VRF = (OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_VRF << 9) | 6,
  OXM_TLV_EXPR_LMEP_ID =
      (OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_LMEP_ID << 9) | 8,
  OXM_TLV_EXPR_OVID = (OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_OVID << 9) | 6,
  OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION =
      (OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_ALLOW_VLAN_TRANSLATION << 9) | 5,
  OXM_TLV_EXPR_ACTSET_OUTPUT =
      (OFPXMC_EXPERIMENTER << 16) | (OFDPA_OXM_ACTSET_OUTPUT << 9) | 8,
};

class coxmatch_ofb_vrf : public coxmatch_exp {
public:
  coxmatch_ofb_vrf(uint16_t vrf)
      : coxmatch_exp(OXM_TLV_EXPR_VRF, EXP_ID_BCM, vrf) {}

  coxmatch_ofb_vrf(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_vrf() {}
};

class coxmatch_ofb_allow_vlan_translation : public coxmatch_exp {
public:
  coxmatch_ofb_allow_vlan_translation(uint8_t val)
      : coxmatch_exp(OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION, EXP_ID_BCM, val) {}

  coxmatch_ofb_allow_vlan_translation(const coxmatch_exp &oxm)
      : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_allow_vlan_translation() {}
};

class coxmatch_ofb_actset_output : public coxmatch_exp {
public:
  coxmatch_ofb_actset_output(uint32_t port)
      : coxmatch_exp(OXM_TLV_EXPR_ACTSET_OUTPUT, ONF_EXP_ID_ONF, port) {}

  coxmatch_ofb_actset_output(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_actset_output() {}
};

class coxmatch_ofb_lmep_id : public coxmatch_exp {
public:
  coxmatch_ofb_lmep_id(uint32_t lmep_id)
      : coxmatch_exp(OXM_TLV_EXPR_LMEP_ID, EXP_ID_BCM, lmep_id) {}

  coxmatch_ofb_lmep_id(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_lmep_id() {}
};

class coxmatch_ofb_ovid : public coxmatch_exp {
public:
  coxmatch_ofb_ovid(uint16_t ovid)
      : coxmatch_exp(OXM_TLV_EXPR_OVID, EXP_ID_BCM, ovid) {}

  coxmatch_ofb_ovid(const coxmatch_exp &oxm) : coxmatch_exp(oxm) {}

  virtual ~coxmatch_ofb_ovid() {}
};

} // end of namespace ofdpa

static inline uint64_t gen_flow_mod_type_cookie(uint64_t val) {
  return (val << 8 * 7);
}

rofl_ofdpa_fm_driver::rofl_ofdpa_fm_driver() {}

rofl_ofdpa_fm_driver::~rofl_ofdpa_fm_driver() {}

cofflowmod rofl_ofdpa_fm_driver::enable_overlay_tunnel(uint8_t ofp_version,
                                                       uint32_t tunnel_id) {
  cofflowmod fm(ofp_version);
  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_INGRESS_PORT);
  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_INGRESS_PORT_OVERLAY_TUNNEL) | 0);

  fm.set_match().set_tunnel_id(tunnel_id);
  ofdpa::coxmatch_ofb_lmep_id exp_match(0);
  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_LMEP_ID) = exp_match;

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_BRIDGING);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_overlay_tunnel(uint8_t ofp_version,
                                                        uint32_t tunnel_id) {
  cofflowmod fm(ofp_version);
  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_INGRESS_PORT);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_INGRESS_PORT_OVERLAY_TUNNEL) | 0);

  fm.set_match().set_tunnel_id(tunnel_id);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_port_pvid_ingress(uint8_t ofp_version,
                                                          uint32_t port_no,
                                                          uint16_t vid,
                                                          uint16_t vrf_id) {
  // check params
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);
  cindex i(0);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(
          OFDPA_FTT_VLAN_VLAN_ASSIGNMENT_UNTAGGED_PORT_VLAN_ASSIGNMENT) |
      0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(0);

  if (vrf_id) {
    fm.set_instructions()
        .set_inst_apply_actions()
        .set_actions()
        .add_action_set_field(i++)
        .set_oxm(ofdpa::coxmatch_ofb_vrf(vrf_id));
  }

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_set_field(i)
      .set_oxm(coxmatch_ofb_vlan_vid(OFPVID_PRESENT | vid));

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_port_pvid_ingress(uint8_t ofp_version,
                                                           uint32_t port_no,
                                                           uint16_t vid) {
  // check params
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(
          OFDPA_FTT_VLAN_VLAN_ASSIGNMENT_UNTAGGED_PORT_VLAN_ASSIGNMENT) |
      0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(0);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_port_vid_ingress(uint8_t ofp_version,
                                                         uint32_t port_no,
                                                         uint16_t vid,
                                                         uint16_t vrf_id,
                                                         bool pop_tag) {
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);

  // TODO check what happens if this is added two times?
  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  if (pop_tag)
    fm.set_cookie(
        gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_TRANSLATE_DOUBLE_TAG) | 0);
  else
    fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_FILTERING) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);

  cindex i(0);
  if (vrf_id != 0) {
    fm.set_instructions()
        .set_inst_apply_actions()
        .set_actions()
        .add_action_set_field(cindex(i++))
        .set_oxm(ofdpa::coxmatch_ofb_vrf(vrf_id));
  }

  if (pop_tag) {
    // this does not actually pop the tag, but OF-DPA wants it that way
    fm.set_instructions()
        .set_inst_apply_actions()
        .set_actions()
        .add_action_pop_vlan(cindex(i++));

    // we are popping the O(uter) VID
    fm.set_instructions()
        .set_inst_apply_actions()
        .set_actions()
        .add_action_set_field(cindex(i++))
        .set_oxm(ofdpa::coxmatch_ofb_ovid(OFPVID_PRESENT | vid));

    // VLAN_1 triggers the actual double tag -> single tag conversion
    fm.set_instructions().set_inst_goto_table().set_table_id(
        OFDPA_FLOW_TABLE_ID_VLAN_1);
  } else {
    fm.set_instructions().set_inst_goto_table().set_table_id(
        OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_port_vid_ingress(uint8_t ofp_version,
                                                          uint32_t port_no,
                                                          uint16_t vid,
                                                          uint16_t vrf_id,
                                                          bool pop_tag) {
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(3);
  if (pop_tag)
    fm.set_cookie(
        gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_TRANSLATE_DOUBLE_TAG) | 0);
  else
    fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_FILTERING) | 0);

  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_port_pop_tag_ingress(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid, uint16_t ovid,
    uint16_t vrf_id) {
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN_1);

  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_VLAN_1_TRANSLATE_DOUBLE_TAG_TO_SINGLE_TAG) |
                0);

  // match on both O(outer) VID and inner VID
  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);
  fm.set_match().set_matches().set_exp_match(EXP_ID_BCM,
                                             ofdpa::OXM_TLV_EXPR_OVID) =
      ofdpa::coxmatch_ofb_ovid(OFPVID_PRESENT | ovid);

  // no VLAN actions means delete inner tag, then add match VID as outer tag

  if (vrf_id != 0) {
    fm.set_instructions()
        .set_inst_apply_actions()
        .set_actions()
        .add_action_set_field(cindex(0))
        .set_oxm(ofdpa::coxmatch_ofb_vrf(vrf_id));
  }

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_port_pop_tag_ingress(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid, uint16_t ovid,
    uint16_t vrf_id) {
  assert(vid < 0x1000);
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN_1);

  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_VLAN_1_TRANSLATE_DOUBLE_TAG_TO_SINGLE_TAG) |
                0);
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);
  fm.set_match().set_matches().set_exp_match(EXP_ID_BCM,
                                             ofdpa::OXM_TLV_EXPR_OVID) =
      ofdpa::coxmatch_ofb_ovid(OFPVID_PRESENT | ovid);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_port_vid_allow_all(uint8_t ofp_version,
                                                           uint32_t port_no) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(7);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_ALLOW_ALL) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT, OFPVID_PRESENT);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_port_vid_allow_all(uint8_t ofp_version,
                                                            uint32_t port_no) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_VLAN);

  fm.set_priority(7);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_VLAN_VLAN_ALLOW_ALL) | 0);

  fm.set_match().set_in_port(port_no);
  fm.set_match().set_vlan_vid(OFPVID_PRESENT, OFPVID_PRESENT);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_tmac_ipv4_unicast_mac(
    uint8_t ofp_version, uint32_t in_port, uint16_t vid,
    const caddress_ll &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV4_UNICAST_MAC) | 0);

  if (in_port)
    fm.set_match().set_in_port(in_port);
  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  fm.set_match().set_eth_dst(mac);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::enable_tmac_ipv4_multicast_mac(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV4_MULTICAST_MAC) |
      0);

  caddress_ll mcast_mac("01:00:5e:00:00:00");
  caddress_ll mask("ff:ff:ff:80:00:00");
  fm.set_match().set_eth_dst(mcast_mac, mask);
  fm.set_match().set_eth_type(ETH_P_IP);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::disable_tmac_ipv4_multicast_mac(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV4_MULTICAST_MAC) |
      0);

  caddress_ll mcast_mac("01:00:5e:00:00:00");
  caddress_ll mask("ff:ff:ff:80:00:00");
  fm.set_match().set_eth_dst(mcast_mac, mask);
  fm.set_match().set_eth_type(ETH_P_IP);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::enable_tmac_ipv6_multicast_mac(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV6_MULTICAST_MAC) |
      0);

  caddress_ll mcast_mac("33:33:00:00:00:00");
  caddress_ll mask("ff:ff:00:00:00:00");
  fm.set_match().set_eth_dst(mcast_mac, mask);
  fm.set_match().set_eth_type(ETH_P_IPV6);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::disable_tmac_ipv6_multicast_mac(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV6_MULTICAST_MAC) |
      0);

  caddress_ll mcast_mac("33:33:00:00:00:00");
  caddress_ll mask("ff:ff:00:00:00:00");
  fm.set_match().set_eth_dst(mcast_mac, mask);
  fm.set_match().set_eth_type(ETH_P_IPV6);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_tmac_ipv6_unicast_mac(
    uint8_t ofp_version, uint32_t in_port, uint16_t vid,
    const caddress_ll &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV6_UNICAST_MAC) | 0);

  if (in_port)
    fm.set_match().set_in_port(in_port);
  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  fm.set_match().set_eth_dst(mac);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_tmac_ipv4_unicast_mac(
    uint8_t ofp_version, uint32_t in_port, uint16_t vid,
    const caddress_ll &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV4_UNICAST_MAC) | 0);

  if (in_port)
    fm.set_match().set_in_port(in_port);
  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  fm.set_match().set_eth_dst(mac);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_tmac_ipv6_unicast_mac(
    uint8_t ofp_version, uint32_t in_port, uint16_t vid,
    const caddress_ll &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_TERMINATION_MAC);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_TERMINATION_MAC_IPV6_UNICAST_MAC) | 0);

  if (in_port)
    fm.set_match().set_in_port(in_port);
  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  fm.set_match().set_eth_dst(mac);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::add_bridging_multicast_vlan(
    uint8_t ofp_version, uint32_t index, uint16_t vid, const cmacaddr &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_MULTICAST_VLAN) |
                index);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  uint32_t group_id = group_id_l2_multicast(index, vid);
  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(cindex(0))
      .set_group_id(group_id);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_multicast_vlan(
    uint8_t ofp_version, uint32_t port, uint16_t vid, const cmacaddr &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_MULTICAST_VLAN) |
                port);

  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv4_unicast_host(
    uint8_t ofp_version, const caddress_in4 &dst, uint32_t group, bool update,
    uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV4_UNICAST_HOST) |
      0);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  if (group) {
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_group(cindex(1))
        .set_group_id(group);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_dec_nw_ttl(cindex(0));
  } else {
    // send to controller
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(OFPP_CONTROLLER);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_output(cindex(0))
        .set_max_len(max_len);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv4_unicast_host(
    uint8_t ofp_version, const caddress_in4 &dst, uint16_t vrf_id) {

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV4_UNICAST_HOST) |
      0);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv4_unicast_lpm(
    uint8_t ofp_version, const caddress_in4 &dst, const caddress_in4 &mask,
    uint32_t group, bool update, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(update ? OFPFC_MODIFY_STRICT : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV4_UNICAST_LPM) | 0);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst, mask);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  if (group) {
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_group(cindex(0))
        .set_group_id(group);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_dec_nw_ttl(cindex(1));
  } else {
    // send to controller
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(OFPP_CONTROLLER);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_output(cindex(0))
        .set_max_len(max_len);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv4_unicast_lpm(
    uint8_t ofp_version, const caddress_in4 &dst, const caddress_in4 &mask,
    uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE_STRICT);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV4_UNICAST_LPM) | 0);
  fm.set_cookie_mask(-1);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst, mask);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv6_unicast_host(
    uint8_t ofp_version, const caddress_in6 &dst, uint32_t group, bool update,
    uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV6_UNICAST_HOST) |
      0);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  if (group) {
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_group(cindex(1))
        .set_group_id(group);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_dec_nw_ttl(cindex(0));
  } else {
    // send to controller
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(OFPP_CONTROLLER);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_output(cindex(0))
        .set_max_len(max_len);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv6_unicast_host(
    uint8_t ofp_version, const caddress_in6 &dst, uint16_t vrf_id) {

  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_priority(3);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV6_UNICAST_HOST) |
      0);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv6_unicast_lpm(
    uint8_t ofp_version, const caddress_in6 &dst, const caddress_in6 &mask,
    uint32_t group, bool update, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(update ? OFPFC_MODIFY_STRICT : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV6_UNICAST_LPM) | 0);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst, mask);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  if (group) {
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_group(cindex(0))
        .set_group_id(group);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_dec_nw_ttl(cindex(1));
  } else {
    // send to controller
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(OFPP_CONTROLLER);
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_output(cindex(0))
        .set_max_len(max_len);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv6_unicast_lpm(
    uint8_t ofp_version, const caddress_in6 &dst, const caddress_in6 &mask,
    uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE_STRICT);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING);

  fm.set_priority(2);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_UNICAST_ROUTING_IPV6_UNICAST_LPM) | 0);
  fm.set_cookie_mask(-1);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst, mask);

  // match VRF
  if (vrf_id != 0) {
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l3_multicast(uint8_t ofp_version,
                                                            uint32_t port_id,
                                                            uint16_t vid) {
  uint32_t group_id = group_id_l3_multicast(port_id, vid);
  cofgroupmod gm(ofp_version);
  cindex i(0);

  gm.set_command(OFPGC_ADD);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_group(i++)
      .set_group_id(group_id_l2_interface(port_id, vid));

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(coxmatch_ofb_vlan_vid(OFPVID_PRESENT | vid));

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l3_multicast(
    uint8_t ofp_version, uint32_t port_id, uint16_t vid) {
  uint32_t group_id = group_id_l3_multicast(port_id, vid);
  cofgroupmod gm(ofp_version);
  cindex i(0);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv4_multicast_host(
    uint8_t ofp_version, uint32_t id, uint16_t vid, const caddress_in4 &dst,
    bool update, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);
  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_MULTICAST_ROUTING_IPV4_MULTICAST) | 0);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  uint32_t group_id = group_id_l3_multicast(id, vid);
  if (group_id)
    fm.set_instructions()
        .set_inst_write_actions()
        .set_actions()
        .set_action_group(cindex(1))
        .set_group_id(group_id);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  // match VRF
  if (vrf_id != 0)
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv4_multicast_host(
    uint8_t ofp_version, const caddress_in4 &dst, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_MULTICAST_ROUTING_IPV6_MULTICAST) | 0);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst);

  // match VRF
  if (vrf_id != 0)
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_ipv6_multicast_host(
    uint8_t ofp_version, uint32_t id, uint16_t vid, const caddress_in6 &dst,
    bool update, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);
  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_MULTICAST_ROUTING_IPV6_MULTICAST) | 0);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  uint32_t group_id = group_id_l3_multicast(id, vid);
  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .set_action_group(cindex(1))
      .set_group_id(group_id);

  // match VRF
  if (vrf_id != 0)
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_ipv6_multicast_host(
    uint8_t ofp_version, const caddress_in6 &dst, uint16_t vrf_id) {
  cofflowmod fm(ofp_version);

  fm.set_command(OFPFC_DELETE);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING);
  fm.set_cookie(
      gen_flow_mod_type_cookie(OFDPA_FTT_MULTICAST_ROUTING_IPV6_MULTICAST) | 0);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst);

  // match VRF
  if (vrf_id != 0)
    fm.set_match().set_matches().set_exp_match(
        EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_VRF) = ofdpa::coxmatch_ofb_vrf(vrf_id);

  return fm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_interface(uint8_t ofp_version,
                                                            uint32_t port_no,
                                                            uint16_t vid,
                                                            bool untagged,
                                                            bool update) {
  assert(vid < 0x1000);
  uint32_t group_id = group_id_l2_interface(port_no, vid);
  cofgroupmod gm(ofp_version);

  gm.set_command(update ? OFPGC_MODIFY : OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  cindex i(0);
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

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_interface(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid) {
  assert(vid < 0x1000);
  uint32_t group_id = group_id_l2_interface(port_no, vid);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod
rofl_ofdpa_fm_driver::enable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                           uint32_t port_no) {
  uint32_t group_id = group_id_l2_unfiltered_interface(port_no);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  cindex i(0);

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

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod
rofl_ofdpa_fm_driver::disable_group_l2_unfiltered_interface(uint8_t ofp_version,
                                                            uint32_t port_no) {
  uint32_t group_id = group_id_l2_unfiltered_interface(port_no);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_rewrite(
    uint8_t ofp_version, uint32_t id, uint32_t port_group_id, uint16_t vid,
    const cmacaddr src_mac, const cmacaddr dst_mac) {

  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_rewrite(id);

  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  cofactions &action_set = gm.set_buckets().add_bucket(bucket_id).set_actions();

  if (vid != 0) {
    action_set.add_action_set_field(cindex(0)).set_oxm(
        coxmatch_ofb_vlan_vid(OFPVID_PRESENT | vid));
  }

  if (src_mac.str() != "00:00:00:00:00:00") {
    action_set.add_action_set_field(cindex(1)).set_oxm(
        coxmatch_ofb_eth_src(src_mac));
  }

  if (dst_mac.str() != "00:00:00:00:00:00") {
    action_set.add_action_set_field(cindex(2)).set_oxm(
        coxmatch_ofb_eth_dst(dst_mac));
  }

  action_set.set_action_group(cindex(3)).set_group_id(port_group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_rewrite(uint8_t ofp_version,
                                                           uint32_t id) {
  uint32_t group_id = group_id_l2_rewrite(id);

  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_multicast(
    uint8_t ofp_version, uint16_t index, uint16_t vid,
    const std::set<uint32_t> &l2_interfaces, bool modify) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_multicast(index, vid);

  cofgroupmod gm(ofp_version);

  gm.set_command(modify ? OFPGC_MODIFY : OFPGC_ADD);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;
  cindex i(0);

  for (const uint32_t &interface : l2_interfaces) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_group(i++)
        .set_group_id(interface);
  }

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod
rofl_ofdpa_fm_driver::disable_group_l2_multicast(uint8_t ofp_version,
                                                 uint16_t index, uint16_t vid) {
  assert(vid < 0x1000);

  cofgroupmod gm(ofp_version);
  uint32_t group_id = group_id_l2_multicast(index, vid);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_flood(
    uint8_t ofp_version, uint16_t vid, uint16_t id,
    const std::set<uint32_t> &l2_interfaces, bool modify) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_flood(id, vid);

  cofgroupmod gm(ofp_version);
  uint16_t command = (modify) ? OFPGC_MODIFY : OFPGC_ADD;
  gm.set_command(command);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  for (const uint32_t &i : l2_interfaces) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_group(cindex(0))
        .set_group_id(i);
  }

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_flood(uint8_t ofp_version,
                                                         uint16_t vid,
                                                         uint16_t id) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_flood(id, vid);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_ALL);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_overlay_flood(
    uint8_t ofp_version, uint16_t tunnel_id, uint16_t index,
    const std::set<uint32_t> &lport_no, bool modify) {
  uint32_t group_id = group_id_l2_overlay_flood(index, tunnel_id);

  cofgroupmod gm(ofp_version);
  uint16_t command = (modify) ? OFPGC_MODIFY : OFPGC_ADD;
  gm.set_command(command);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  for (const uint32_t &i : lport_no) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(i);
  }

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_overlay_flood(
    uint8_t ofp_version, uint16_t tunnel_id, uint16_t index) {
  uint32_t group_id = group_id_l2_overlay_flood(index, tunnel_id);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_overlay_multicast(
    uint8_t ofp_version, uint16_t tunnel_id, uint16_t index,
    const std::set<uint32_t> &lport_no, bool modify) {
  assert(tunnel_id < 0x1000);

  uint32_t group_id = group_id_l2_overlay_multicast(index, tunnel_id);

  cofgroupmod gm(ofp_version);
  uint16_t command = (modify) ? OFPGC_MODIFY : OFPGC_ADD;
  gm.set_command(command);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  uint32_t bucket_id = 0;

  for (const uint32_t &i : lport_no) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_output(cindex(0))
        .set_port_no(i);
  }

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_overlay_multicast(
    uint8_t ofp_version, uint16_t tunnel_id, uint16_t index) {
  assert(tunnel_id < 0x1000);

  uint32_t group_id = group_id_l2_overlay_multicast(index, tunnel_id);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);

  return gm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_ipv6_multicast(
    uint8_t ofp_version, const caddress_in6 &dst, const caddress_in6 &mask) {

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV6_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IPV6);
  fm.set_match().set_ipv6_dst(dst, mask);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_arp(uint8_t ofp_version,
                                                   bool update) {

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_ARP);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_l2(uint8_t ofp_version,
                                                  const rofl::caddress_ll &mac,
                                                  const rofl::caddress_ll &mask) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_dst(mac, mask);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);

  fm.set_instructions().set_inst_clear_actions();

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_specific_lacp(
    uint8_t ofp_version, const caddress_ll &eth_src,
    const uint16_t timeout_seconds, const uint32_t in_port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(timeout_seconds);
  fm.set_priority(10);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_flags(OFPFF_SEND_FLOW_REM);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_SLOW);
  fm.set_match().set_eth_dst(cmacaddr("01:80:c2:00:00:02"));
  fm.set_match().set_eth_src(eth_src);
  fm.set_match().set_in_port(in_port);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);
  fm.set_instructions().set_inst_clear_actions();

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_8021d(uint8_t ofp_version,
                                                     bool update) {

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(8);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(update ? OFPFC_MODIFY : OFPFC_ADD);

  /* 01-80-C2-00-00-00 to 01-80-C2-00-00-0F must not be forwarded by bridges
   * according to IEEE 802.1D */
  fm.set_match().set_eth_dst(cmacaddr("01:80:c2:00:00:00"),
                             cmacaddr("ff:ff:ff:ff:ff:f0"));

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);
  fm.set_instructions().set_inst_clear_actions();

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_policy_8021d(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_priority(8);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_DELETE);

  /* 01-80-C2-00-00-00 to 01-80-C2-00-00-0F must not be forwarded by bridges
   * according to IEEE 802.1D */
  fm.set_match().set_eth_dst(cmacaddr("01:80:c2:00:00:00"),
                             cmacaddr("ff:ff:ff:ff:ff:f0"));

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_policy_l2(uint8_t ofp_version,
                                                   const rofl::caddress_ll &mac,
                                                   const rofl::caddress_ll &mask) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_eth_dst(mac, mask);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::disable_policy_specific_lacp(uint8_t ofp_version,
                                                   const uint32_t in_port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);
  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_eth_type(ETH_P_SLOW);
  fm.set_match().set_eth_dst(cmacaddr("01:80:c2:00:00:02"));
  fm.set_match().set_in_port(in_port);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_udp(
    uint8_t ofp_version, uint16_t eth_type, int16_t src_port, int16_t dst_port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  if (eth_type == ETH_P_IP)
    fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);
  else
    fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV6_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(eth_type);

  fm.set_match().set_ip_proto(IPPROTO_UDP);
  fm.set_match().set_udp_src(src_port);
  fm.set_match().set_udp_dst(dst_port);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_broadcast_udp(
    uint8_t ofp_version, int16_t src_port, int16_t dst_port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IP);

  fm.set_match().set_ipv4_dst(caddress_in4(std::string("255.255.255.255")));
  fm.set_match().set_ip_proto(IPPROTO_UDP);
  fm.set_match().set_udp_src(src_port); // bootpc
  fm.set_match().set_udp_dst(dst_port); // bootps

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_vrrp(uint8_t ofp_version) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IP);

  fm.set_match().set_ipv4_dst(caddress_in4(std::string("224.0.0.18")));
  fm.set_match().set_ip_proto(IPPROTO_VRRP);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .set_action_output(cindex(0))
      .set_max_len(max_len);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_policy_ipv4_multicast(
    uint8_t ofp_version, const caddress_in4 &dst, const caddress_in4 &mask) {

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_POLICY_ACL_IPV4_VLAN) | 0);

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_eth_type(ETH_P_IP);
  fm.set_match().set_ipv4_dst(dst, mask);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(OFPP_CONTROLLER);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_send_to_l2_rewrite(
    uint8_t ofp_version, uint16_t vid, const caddress_ll &dst,
    uint32_t group_id, uint64_t cookie) {
  // TODO add checks

  cofmatch match(ofp_version);
  match.set_vlan_vid(vid | OFPVID_PRESENT);
  match.set_eth_dst(dst);

  cofactions write_actions(ofp_version);
  write_actions.set_action_group(cindex(0)).set_group_id(group_id);

  return enable_policy_acl_generic(ofp_version, match, false, 0, 0, cookie,
                                   cofactions(), write_actions);
}

cofflowmod rofl_ofdpa_fm_driver::disable_send_to_l2_rewrite(
    uint8_t ofp_version, uint16_t vid, const caddress_ll &dst,
    uint64_t cookie) {
  // TODO add checks

  cofmatch match(ofp_version);
  match.set_vlan_vid(vid | OFPVID_PRESENT);
  match.set_eth_dst(dst);

  return disable_policy_acl_generic(ofp_version, match, cookie);
}

cofflowmod rofl_ofdpa_fm_driver::disable_send_to_l2_rewrite_all(
    uint8_t ofp_version, uint16_t vid, uint64_t cookie) {
  // TODO add checks

  cofmatch match(ofp_version);
  match.set_vlan_vid(vid | OFPVID_PRESENT);

  return disable_policy_acl_generic(ofp_version, match, cookie);
}

// TODO: For future reference:
// The contents of apply_actions and write_actions arguments should be checked,
// rofl-common also currently does not match on VLAN_DEI and VRF.
cofflowmod rofl_ofdpa_fm_driver::enable_policy_acl_generic(
    uint8_t ofp_version, const cofmatch &matches, bool clear_actions,
    uint32_t meter_id, uint32_t table_id, uint64_t cookie,
    const cofactions &apply_actions, const cofactions &write_actions) {

  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);
  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(cookie);
  fm.set_command(OFPFC_ADD);

  if (idle_timeout) {
    fm.set_flags(OFPFF_SEND_FLOW_REM);
  }

  // Matches
  if (matches.has_in_port()) {
    fm.set_match().set_in_port(matches.get_in_port());
  }
  if (matches.has_eth_type()) {
    fm.set_match().set_eth_type(matches.get_eth_type());
  }
  if (matches.has_eth_src_mask() && matches.has_eth_src()) {
    fm.set_match().set_eth_src(matches.get_eth_src(),
                               matches.get_eth_src_mask());
  } else if (matches.has_eth_src()) {
    fm.set_match().set_eth_src(matches.get_eth_src());
  }
  if (matches.has_eth_dst_mask() && matches.has_eth_dst()) {
    fm.set_match().set_eth_dst(matches.get_eth_dst(),
                               matches.get_eth_dst_mask());
  } else if (matches.has_eth_dst()) {
    fm.set_match().set_eth_dst(matches.get_eth_dst());
  }
  if (matches.has_vlan_vid_mask() && matches.has_vlan_vid()) {
    assert((matches.get_vlan_vid() & ~OFPVID_PRESENT) < 0x1000);
    fm.set_match().set_vlan_vid(matches.get_vlan_vid(),
                                matches.get_vlan_vid_mask());
  } else if (matches.has_vlan_vid()) {
    assert((matches.get_vlan_vid_value() & ~OFPVID_PRESENT) < 0x1000);
    fm.set_match().set_vlan_vid(matches.get_vlan_vid());
  }
  if (matches.has_vlan_pcp()) {
    fm.set_match().set_vlan_pcp(matches.get_vlan_pcp());
  }

  // $VLAN_DEI <- MISSING!
  // $VRF <- MISSING!

  if (matches.has_ipv4_src_mask() && matches.has_ipv4_src()) {
    fm.set_match().set_ipv4_src(matches.get_ipv4_src(),
                                matches.get_ipv4_src_mask());
  }
  if (matches.has_ipv4_dst_mask() && matches.has_ipv4_dst()) {
    fm.set_match().set_ipv4_dst(matches.get_ipv4_dst(),
                                matches.get_ipv4_dst_mask());
  }
  if (matches.has_ip_proto()) {
    fm.set_match().set_ip_proto(matches.get_ip_proto());
  }
  if (matches.has_ip_dscp()) {
    fm.set_match().set_ip_dscp(matches.get_ip_dscp());
  }
  if (matches.has_ip_ecn()) {
    fm.set_match().set_ip_ecn(matches.get_ip_ecn());
  }
  if (matches.has_tcp_src()) {
    fm.set_match().set_tcp_src(matches.get_tcp_src());
  }
  if (matches.has_udp_src()) {
    fm.set_match().set_udp_src(matches.get_udp_src());
  }
  if (matches.has_sctp_src()) {
    fm.set_match().set_sctp_src(matches.get_sctp_src());
  }
  if (matches.has_icmpv4_type()) {
    fm.set_match().set_icmpv4_type(matches.get_icmpv4_type());
  }
  if (matches.has_icmpv4_code()) {
    fm.set_match().set_icmpv4_code(matches.get_icmpv4_code());
  }
  if (matches.has_tcp_dst()) {
    fm.set_match().set_tcp_dst(matches.get_tcp_dst());
  }
  if (matches.has_udp_dst()) {
    fm.set_match().set_udp_dst(matches.get_udp_dst());
  }
  if (matches.has_sctp_dst()) {
    fm.set_match().set_sctp_dst(matches.get_sctp_dst());
  }
  if (matches.has_arp_spa_mask() && matches.has_arp_spa()) {
    fm.set_match().set_arp_spa(matches.get_arp_spa(),
                               matches.get_arp_spa_mask());
  }

  // Instructions
  if (meter_id != 0) {
    fm.set_instructions().set_inst_meter().set_meter_id(meter_id);
  }
  if (table_id != 0) {
    fm.set_instructions().set_inst_goto_table().set_table_id(table_id);
  }
  if (clear_actions) {
    fm.set_instructions().set_inst_clear_actions();
  }

  // Allowed apply actions
  // * none or any of fiels set: COLOR_ACTIONS_INDEX, COLOR, SET_FIELD
  // * none or one output: CONTROLLER
  if (apply_actions.size() > 0) {
    fm.set_instructions().set_inst_apply_actions().set_actions() =
        apply_actions;
  }

  // Allowed write actions:
  // * zero or one group
  // * none or any of fields set: IP_DSCP, IP_ECN, VLAN_PCP
  if (write_actions.size() > 0) {
    fm.set_instructions().set_inst_write_actions().set_actions() =
        write_actions;
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_policy_acl_generic(
    uint8_t ofp_version, const cofmatch &matches, uint64_t cookie) {

  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_ACL_POLICY);
  fm.set_priority(2);
  fm.set_cookie(cookie);
  fm.set_cookie_mask(-1);
  fm.set_command(OFPFC_DELETE);

  // TODO VLAN_DEI, VRF
  if (matches.has_in_port()) {
    fm.set_match().set_in_port(matches.get_in_port());
  }
  if (matches.has_eth_type()) {
    fm.set_match().set_eth_type(matches.get_eth_type());
  }
  if (matches.has_eth_src_mask() && matches.has_eth_src()) {
    fm.set_match().set_eth_src(matches.get_eth_src(),
                               matches.get_eth_src_mask());
  } else if (matches.has_eth_src()) {
    fm.set_match().set_eth_src(matches.get_eth_src());
  }
  if (matches.has_eth_dst_mask() && matches.has_eth_dst()) {
    fm.set_match().set_eth_dst(matches.get_eth_dst(),
                               matches.get_eth_dst_mask());
  } else if (matches.has_eth_dst()) {
    fm.set_match().set_eth_dst(matches.get_eth_dst());
  }
  if (matches.has_vlan_vid_mask() && matches.has_vlan_vid()) {
    assert((matches.get_vlan_vid() & ~OFPVID_PRESENT) < 0x1000);
    fm.set_match().set_vlan_vid(matches.get_vlan_vid(),
                                matches.get_vlan_vid_mask());
  } else if (matches.has_vlan_vid()) {
    assert((matches.get_vlan_vid_value() & ~OFPVID_PRESENT) < 0x1000);
    fm.set_match().set_vlan_vid(matches.get_vlan_vid());
  }
  if (matches.has_vlan_pcp()) {
    fm.set_match().set_vlan_pcp(matches.get_vlan_pcp());
  }
  if (matches.has_ipv4_src_mask() && matches.has_ipv4_src()) {
    fm.set_match().set_ipv4_src(matches.get_ipv4_src(),
                                matches.get_ipv4_src_mask());
  }
  if (matches.has_ipv4_dst_mask() && matches.has_ipv4_dst()) {
    fm.set_match().set_ipv4_dst(matches.get_ipv4_dst(),
                                matches.get_ipv4_dst_mask());
  }
  if (matches.has_ip_proto()) {
    fm.set_match().set_ip_proto(matches.get_ip_proto());
  }
  if (matches.has_ip_dscp()) {
    fm.set_match().set_ip_dscp(matches.get_ip_dscp());
  }
  if (matches.has_ip_ecn()) {
    fm.set_match().set_ip_ecn(matches.get_ip_ecn());
  }
  if (matches.has_tcp_src()) {
    fm.set_match().set_tcp_src(matches.get_tcp_src());
  }
  if (matches.has_udp_src()) {
    fm.set_match().set_udp_src(matches.get_udp_src());
  }
  if (matches.has_sctp_src()) {
    fm.set_match().set_sctp_src(matches.get_sctp_src());
  }
  if (matches.has_icmpv4_type()) {
    fm.set_match().set_icmpv4_type(matches.get_icmpv4_type());
  }
  if (matches.has_icmpv4_code()) {
    fm.set_match().set_icmpv4_code(matches.get_icmpv4_code());
  }
  if (matches.has_tcp_dst()) {
    fm.set_match().set_tcp_dst(matches.get_tcp_dst());
  }
  if (matches.has_udp_dst()) {
    fm.set_match().set_udp_dst(matches.get_udp_dst());
  }
  if (matches.has_sctp_dst()) {
    fm.set_match().set_sctp_dst(matches.get_sctp_dst());
  }
  if (matches.has_arp_spa_mask() && matches.has_arp_spa()) {
    fm.set_match().set_arp_spa(matches.get_arp_spa(),
                               matches.get_arp_spa_mask());
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::add_bridging_dlf_vlan(uint8_t ofp_version,
                                                       uint16_t vid,
                                                       uint32_t group_id) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_VLAN));

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(cindex(0))
      .set_group_id(group_id);
  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_dlf_vlan(uint8_t ofp_version,
                                                          uint16_t vid) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_VLAN));
  fm.set_cookie_mask(-1);

  // TODO do this strict?
  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::add_bridging_dlf_overlay(uint8_t ofp_version,
                                                          uint16_t tunnel_id,
                                                          uint32_t group_id) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(4);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_OVERLAY));

  fm.set_command(OFPFC_ADD);

  fm.set_match().set_tunnel_id(tunnel_id);

  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(cindex(0))
      .set_group_id(group_id);
  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod
rofl_ofdpa_fm_driver::remove_bridging_dlf_overlay(uint8_t ofp_version,
                                                  uint16_t tunnel_id) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(4);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_DLF_OVERLAY));
  fm.set_cookie_mask(-1);

  // TODO do this strict?
  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_tunnel_id(tunnel_id);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::add_bridging_unicast_vlan(uint8_t ofp_version,
                                                           uint32_t port_no,
                                                           uint16_t vid,
                                                           const cmacaddr &mac,
                                                           bool filtered, bool lag) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);

  if (idle_timeout) {
    fm.set_flags(OFPFF_SEND_FLOW_REM);
  }

  fm.set_command(OFPFC_ADD);

  // FIXME do not allow multicast mac here?
  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  uint32_t group_id;
  if (lag && filtered) {
    group_id = group_id_l2_trunk_interface(port_no, vid);
  } else if (lag && !filtered) {
    group_id = group_id_l2_trunk_unfiltered_interface(port_no);
  } else if (!lag && filtered) {
    group_id = group_id_l2_interface(port_no, vid);
  } else {
    group_id = group_id_l2_unfiltered_interface(port_no);
  }
  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_group(cindex(0))
      .set_group_id(group_id);
  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_unicast_vlan(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid, const cmacaddr &mac) {
  assert(vid < 0x1000);

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(3);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);

  // TODO do this strict?
  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_unicast_vlan_all(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid) {
  assert(vid < 0x1000 || (uint16_t)-1 == vid);

  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_VLAN) |
                port_no);
  fm.set_cookie_mask(-1);

  // TODO do this strict?
  fm.set_command(OFPFC_DELETE);
  if ((uint16_t)-1 != vid) {
    fm.set_match().set_vlan_vid(vid | OFPVID_PRESENT);
  }

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::add_bridging_unicast_overlay(
    uint8_t ofp_version, uint32_t lport_no, uint32_t tunnel_id,
    const cmacaddr &mac) {
  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);
  fm.set_idle_timeout(idle_timeout);
  fm.set_priority(5);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_OVERLAY) |
                lport_no);
  fm.set_cookie_mask(-1);

  fm.set_command(OFPFC_ADD);

  // XXX TODO check for unicast
  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_tunnel_id(tunnel_id);

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_ACL_POLICY);
  fm.set_instructions()
      .set_inst_write_actions()
      .set_actions()
      .add_action_output(cindex(0))
      .set_port_no(lport_no);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_unicast_overlay(
    uint8_t ofp_version, uint32_t tunnel_id, const cmacaddr &mac) {
  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);
  fm.set_priority(5);

  fm.set_command(OFPFC_DELETE);

  // XXX TODO check for unicast
  fm.set_match().set_eth_dst(mac);
  fm.set_match().set_tunnel_id(tunnel_id);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_unicast_overlay_all_lport(
    uint8_t ofp_version, uint32_t lport_no) {
  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);
  fm.set_priority(5);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_BRIDGING_UNICAST_OVERLAY) |
                lport_no);
  fm.set_cookie_mask(-1);

  fm.set_command(OFPFC_DELETE);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_bridging_unicast_overlay_all_tunnel(
    uint8_t ofp_version, uint32_t tunnel_id) {
  cofflowmod fm(ofp_version);

  fm.set_table_id(OFDPA_FLOW_TABLE_ID_BRIDGING);
  fm.set_priority(5);

  fm.set_command(OFPFC_DELETE);

  fm.set_match().set_tunnel_id(tunnel_id);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::rewrite_vlan_egress(uint8_t ofp_version,
                                                     uint32_t backup_port,
                                                     uint16_t old_vid,
                                                     uint16_t new_vid) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG) |
                0);

  fm.set_command(OFPFC_ADD);

  ofdpa::coxmatch_ofb_actset_output exp_match(backup_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(OFPVID_PRESENT | old_vid);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_set_field(cindex(0))
      .set_oxm(coxmatch_ofb_vlan_vid(OFPVID_PRESENT | new_vid));

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::remove_rewritten_vlan_egress(
    uint8_t ofp_version, uint32_t backup_port, uint16_t old_vid,
    uint16_t new_vid) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);

  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG) |
                0);

  fm.set_command(OFPFC_DELETE);

  ofdpa::coxmatch_ofb_actset_output exp_match(backup_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(OFPVID_PRESENT | old_vid);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::enable_vlan_egress_push_tag(
    uint8_t ofp_version, uint32_t out_port, uint16_t vid, uint16_t ovid) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG) |
                0);

  fm.set_command(OFPFC_ADD);

  ofdpa::coxmatch_ofb_actset_output exp_match(out_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);

  // OF-DPA requires the pushed tag to be 802.1Q (0x8100), so a follow up TPID
  // flow is needed to rewrite to 802.1AD (0x88a8)
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_push_vlan(cindex(0))
      .set_eth_type(ETH_P_8021Q);

  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_set_field(cindex(1))
      .set_oxm(coxmatch_ofb_vlan_vid(OFPVID_PRESENT | ovid));

  fm.set_instructions().set_inst_goto_table().set_table_id(
      OFDPA_FLOW_TABLE_ID_EGRESS_DSCP_PCP_REMARK);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);

  return fm;
}

cofflowmod rofl_ofdpa_fm_driver::disable_vlan_egress_push_tag(
    uint8_t ofp_version, uint32_t out_port, uint16_t vid, uint16_t ovid) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_VLAN);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(
                    OFDPA_FTT_EGRESS_VLAN_VLAN_TRANSLATE_SINGLE_TAG) |
                0);

  fm.set_command(OFPFC_DELETE);

  ofdpa::coxmatch_ofb_actset_output exp_match(out_port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_matches().set_exp_match(
      EXP_ID_BCM, ofdpa::OXM_TLV_EXPR_ALLOW_VLAN_TRANSLATION) =
      ofdpa::coxmatch_ofb_allow_vlan_translation(1);

  fm.set_match().set_vlan_vid(OFPVID_PRESENT | vid);

  return fm;
}

/*
 *  OFPDA helper function to set the TPID on the port.
 *  OFPDA does not have a specific set-field action for the TPID,
 *  we have to follow the spec for the specific apply actions order
 *
 *  The two defined matches are OFPVID_PRESENT with mask OFPVID_PRESENT,
 *  and output port.
 *
 *  @param ofp_version Defines the current openflow version supported
 *  @param port The expected output port for the Flowmod
 * */
cofflowmod rofl_ofdpa_fm_driver::set_port_tpid(uint8_t ofp_version,
                                               uint32_t port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_TPID);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_EGRESS_TPID_STAG) | 0);

  fm.set_command(OFPFC_ADD);

  ofdpa::coxmatch_ofb_actset_output exp_match(port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_vlan_vid(OFPVID_PRESENT, OFPVID_PRESENT);

  /*
  Copy Field - PACKET_REG(1)  - Copy the VLAN Id to a temporary register.
  POP VLAN - None - After copying the VLAN Id, pops the tag.
  PUSH VLAN - ETH_TYPE - Must be 0x88a8.
  Set-Field - PACKET_REG(1) - Sets the VLAN Id to the copied value.
  */

  cofaction_experimenter action;
  cofaction_experimenter restore;

  action.set_version(rofl::openflow13::OFP_VERSION);
  restore.set_version(rofl::openflow13::OFP_VERSION);

  action.set_exp_id(0x4F4E4600);
  restore.set_exp_id(0x4F4E4600);

  experimental::ext320::cofaction_body_copy_field copy_field(
      /*n_bits         =*/16,
      /*src_offset     =*/0,
      /*dst_offset     =*/0,
      /*src_oxm_id     =*/OXM_TLV_CLASS_TYPE(OXM_TLV_BASIC_VLAN_VID),
      /*src_oxm_exp_id =*/0,
      /*dst_oxm_id     =*/OXM_TLV_CLASS_TYPE(OXM_TLV_PKTREG(1)),
      /*dst_oxm_exp_id =*/0);

  experimental::ext320::cofaction_body_copy_field restore_field(
      /*n_bits         =*/16,
      /*src_offset     =*/0,
      /*dst_offset     =*/0,
      /*src_oxm_id     =*/OXM_TLV_CLASS_TYPE(OXM_TLV_PKTREG(1)),
      /*src_oxm_exp_id =*/0,
      /*dst_oxm_id     =*/OXM_TLV_CLASS_TYPE(OXM_TLV_BASIC_VLAN_VID),
      /*dst_oxm_exp_id =*/0);

  action.set_exp_body() = copy_field;
  restore.set_exp_body() = restore_field;

  // copy field: store VLAN_VID in PacketRegister(1)
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_experimenter(cindex(0)) = action;

  // pop vlan
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_pop_vlan(cindex(1));

  // push vlan S-TAG according to "IEEE 802.1ad" (0x88a8)
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_push_vlan(cindex(2))
      .set_eth_type(ETH_P_8021AD);

  // copy field: restore VLAN_VID from PacketRegister(1)
  fm.set_instructions()
      .set_inst_apply_actions()
      .set_actions()
      .add_action_experimenter(cindex(3)) = restore;

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);
  return fm;
}

/*
 *  OFPDA helper function to delete the TPID on the port.
 *  OFPDA does not have a specific set-field action for the TPID,
 *  we have to follow the spec for the specific apply actions order
 *
 *  The two defined matches are OFPVID_PRESENT with mask OFPVID_PRESENT,
 *  and output port.
 *
 *  @param ofp_version Defines the current openflow version supported
 *  @param port The expected output port for the Flowmod
 * */
cofflowmod rofl_ofdpa_fm_driver::remove_port_tpid(uint8_t ofp_version,
                                                  uint32_t port) {
  cofflowmod fm(ofp_version);
  fm.set_table_id(OFDPA_FLOW_TABLE_ID_EGRESS_TPID);
  fm.set_priority(2);
  fm.set_cookie(gen_flow_mod_type_cookie(OFDPA_FTT_EGRESS_TPID_STAG) | 0);

  fm.set_command(OFPFC_DELETE);

  ofdpa::coxmatch_ofb_actset_output exp_match(port);
  fm.set_match().set_matches().set_exp_match(
      ONF_EXP_ID_ONF, ofdpa::OXM_TLV_EXPR_ACTSET_OUTPUT) = exp_match;

  fm.set_match().set_vlan_vid(OFPVID_PRESENT, OFPVID_PRESENT);

  DEBUG_LOG(": return flow-mod:" << std::endl << fm);
  return fm;
}

cofgroupmod
rofl_ofdpa_fm_driver::enable_group_l3_ecmp(uint8_t ofp_version, uint32_t id,
                                           const std::set<uint32_t> l3_unicast,
                                           bool modify) {
  cofgroupmod gm(ofp_version);
  uint32_t group_id = group_id_l3_ecmp(id);
  uint32_t bucket_id = 0;

  if (modify) {
    gm.set_command(OFPGC_MODIFY);
  } else {
    gm.set_command(OFPGC_ADD);
  }

  gm.set_type(OFPGT_SELECT);
  gm.set_group_id(group_id);

  for (const uint32_t &i : l3_unicast) {
    gm.set_buckets()
        .add_bucket(bucket_id++)
        .set_actions()
        .add_action_group(cindex(0))
        .set_group_id(i);
  }

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l3_ecmp(uint8_t ofp_version,
                                                        uint32_t id) {
  cofgroupmod gm(ofp_version);
  uint32_t group_id = group_id_l3_ecmp(id);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_SELECT);
  gm.set_group_id(group_id);

  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l3_unicast(
    uint8_t ofp_version, uint32_t id, const caddress_ll &src_mac,
    const cmacaddr &dst_mac, uint32_t l2_interface, bool modify) {
  uint32_t group_id = group_id_l3_unicast(id);
  cofgroupmod gm(ofp_version);

  assert(0 == get_group_type(l2_interface) || /* l2 */
      11 == get_group_type(l2_interface) || /* l2 unfiltered */
      12 == get_group_type(l2_interface) || /* trunk */
      13 == get_group_type(l2_interface)); /* trunk unfiltered */

  if (modify) {
    gm.set_command(OFPGC_MODIFY);
  } else {
    gm.set_command(OFPGC_ADD);
  }

  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  cindex i(0);
  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(coxmatch_ofb_eth_src(src_mac));

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(coxmatch_ofb_eth_dst(dst_mac));

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(
          coxmatch_ofb_vlan_vid(OFPVID_PRESENT | get_group_vid(l2_interface)));

  gm.set_buckets().set_bucket(0).set_actions().add_action_group(i).set_group_id(
      l2_interface);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l3_unicast(uint8_t ofp_version,
                                                           uint32_t id) {
  uint32_t group_id = group_id_l3_unicast(id);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l3_interface(
    uint8_t ofp_version, uint32_t id, const caddress_ll &src_mac,
    uint32_t l2_interface, const cmacaddr &dst_mac) {

  uint32_t group_id = group_id_l3_interface(id);
  cofgroupmod gm(ofp_version);

  assert(5 == get_group_type(l2_interface) &&
         "wrong l2 group in enable_group_l3_interface");

  gm.set_command(OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  cindex i(0);
  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(coxmatch_ofb_eth_src(src_mac));

  if (dst_mac != caddress_ll("00:00:00:00:00:00")) {
    gm.set_buckets()
        .set_bucket(0)
        .set_actions()
        .add_action_set_field(i++)
        .set_oxm(coxmatch_ofb_eth_dst(dst_mac));
  }

  gm.set_buckets()
      .set_bucket(0)
      .set_actions()
      .add_action_set_field(i++)
      .set_oxm(
          coxmatch_ofb_vlan_vid(OFPVID_PRESENT | get_group_vid(l2_interface)));

  gm.set_buckets().set_bucket(0).set_actions().add_action_group(i).set_group_id(
      l2_interface);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod
rofl_ofdpa_fm_driver::disable_group_l3_interface(uint8_t ofp_version,
                                                 uint32_t id) {

  uint32_t group_id = group_id_l3_interface(id);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_trunk_interface(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid, bool untagged,
    bool update) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_trunk_interface(port_no, vid);
  cofgroupmod gm(ofp_version);

  gm.set_command(update ? OFPGC_MODIFY : OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  cindex i(0);
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

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_trunk_interface(
    uint8_t ofp_version, uint32_t port_no, uint16_t vid) {
  assert(vid < 0x1000);

  uint32_t group_id = group_id_l2_trunk_interface(port_no, vid);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

cofgroupmod rofl_ofdpa_fm_driver::enable_group_l2_trunk_unfiltered_interface(uint8_t ofp_version,
                                            uint32_t port_no) {
  uint32_t group_id = group_id_l2_trunk_unfiltered_interface(port_no);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_ADD);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}
cofgroupmod rofl_ofdpa_fm_driver::disable_group_l2_trunk_unfiltered_interface(uint8_t ofp_version,
                                             uint32_t port_no){
  uint32_t group_id = group_id_l2_trunk_unfiltered_interface(port_no);
  cofgroupmod gm(ofp_version);

  gm.set_command(OFPGC_DELETE);
  gm.set_type(OFPGT_INDIRECT);
  gm.set_group_id(group_id);

  DEBUG_LOG(": return group-mod:" << std::endl << gm);
  return gm;
}

} /* namespace openflow */
} /* namespace rofl */
