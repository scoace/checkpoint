import CP
import pprint 
import base64
import credentials
import json


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password


client=CP.CP(ipaddr,username, password)

hosts=client.get_hosts()

for host in hosts:
    pprint.pprint (host)
    print("-----------------------------------------------------------------")

with open("hosts.json", "w", encoding="utf-8") as f:
    json.dump(hosts, f, ensure_ascii=False, indent=2)