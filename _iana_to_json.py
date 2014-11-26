#!/usr/bin/env python

import csv
import json

with open("iana_tls-params_min.csv") as f:
    ciphers = []
    idx = 0
    csv_r = csv.reader(f)
    for row in csv_r:
        value = int(row[0],16) * 256 + int(row[1],16)
        ciphers.append( { 'index': idx, 'value': value, 'name': row[2]} )
        idx += 1

# write json
#with open("iana_tls-params_min.json", "w") as outf:
#    json.dump(ciphers, outf, indent=2)

print("// all IANA registered cyphers, indexed by position in list")
print("var CiphersByIndex map[uint]CipherSuite = map[uint]CipherSuite{")
for c in ciphers:
    print( "  %d: CipherSuite{Index: %d, Value: %d, Name: \"%s\"}," % (c['index'], c['index'], c['value'], c['name']) )

print("}\n")

print("// all IANA registered cyphers, indexed by identifier")
print("var CiphersByValue map[uint]CipherSuite = map[uint]CipherSuite{")
for c in ciphers:
    print( "  %d: CipherSuite{Index: %d, Value: %d, Name: \"%s\"}," % (c['value'], c['index'], c['value'], c['name']) )

print("}\n")
