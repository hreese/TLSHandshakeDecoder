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

with open("iana_tls-params_min.json", "w") as outf:
    json.dump(ciphers, outf, indent=2)

