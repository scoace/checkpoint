import CP
import pprint 
import base64
import credentials
import json


#ipaddr=credentials.ipaddr
#username=credentials.username
#password=credentials.password

ip=credentials.ipaddr
api_key=credentials.api_key
cloud_mgmt=credentials.cloud_mgmt_id



client=CP.CP(ipaddr=ip,api_key=api_key, cloud_mgmt_id=cloud_mgmt)

#client=CP.CP(ipaddr,username, password)
commands=client.call_api("show-commands",{
  
})
mydict = commands.as_dict()
print (mydict['data']['commands'])
for item in mydict['data']['commands']:
    print ("{}: {}".format(item['name'], item['description']))

with open("commands.txt", "w", encoding="utf-8") as f:
    json.dump(mydict['data']['commands'], f, ensure_ascii=False, indent=2)