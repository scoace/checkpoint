import CP
import pprint 
import base64
import credentials
import json


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

#ip=credentials.ipaddr
#api_key=credentials.api_key
#cloud_mgmt=credentials.cloud_mgmt_id



#client=CP.CP(ipaddr=ip,api_key=api_key, cloud_mgmt_id=cloud_mgmt)
client=CP.CP(ipaddr,username=username, password=password)
hosts=client.get_hosts()

for host in hosts:
    pprint.pprint (host)
    print("-----------------------------------------------------------------")

with open("hosts.json", "w", encoding="utf-8") as f:
    json.dump(hosts, f, ensure_ascii=False, indent=2)