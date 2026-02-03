import CP
import pprint 
import base64
import credentials
import json


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password


client=CP.CP(ipaddr,username, password)

tcp_services=client.get_tcp_services_dict()

for service in tcp_services:
    pprint.pprint (service)
    print("-----------------------------------------------------------------")

with open("tcp_services.json", "w", encoding="utf-8") as f:
    json.dump(tcp_services, f, ensure_ascii=False, indent=2)
