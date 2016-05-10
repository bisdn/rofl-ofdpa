#!/usr/bin/env python3

import json
import re

def encode_name(prefix, name):
    encoded_name = prefix
    encoded_name += re.sub(r' ', r'_', name.upper())
    encoded_name = re.sub(r'[(|)|-]', '', encoded_name)
    encoded_name = re.sub(r'\.', '_', encoded_name)
    encoded_name = re.sub(r'__+', '_', encoded_name)
    encoded_name = re.sub(r'MPLS-TP', r'MPLS', encoded_name)
    return encoded_name

def parse_experimenter_id(identifier):
    print("\t%s = %d," % (encode_name('OFDPA_OXM_', identifier['id']), identifier['exp_code']))

def parse_flow_table(table):
    #print('name: %s' % encode_name('OFDPA_FLOW_TABLE_ID_', table['name']))
    #print('#ids: %d' % len(table['flow_mod_types']))
    print("enum %s {" % encode_name('OFDPA_FLOW_TABLE_ID_FMT_', table['name']))
    for typ in table['flow_mod_types']:
        parse_flow_mod_type(encode_name('', table['name']), typ)
    print("};")

def parse_flow_mod_type(prefix, typ):
    if 'name' in typ:
        name = typ['name']
    elif 'Name' in typ:
        name = typ['Name']
    else:
        name = typ['Rule  Type']
    print("\tOFDPA_FTT_%s_%s," % (prefix, encode_name('', name)))

with open('ofdpa-ttp.json', 'r') as f:
    ofdpa = json.load(f)

print("enum ofdpa_match_exp_type {")
for ident in ofdpa['identifiers']:
    if 'var' in ident:
        # print("var=%s" % ident['var'])
        pass
    elif 'id' in ident:
        if ident['type'] == 'field':
           parse_experimenter_id(ident)
        #print("id=%s" % ident['id'])
print("};")


for table in ofdpa['flow_tables']:
    parse_flow_table(table)



