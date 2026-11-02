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

response=client.call_api("run-script",{
  "script-name" : "Script Example: List files under / dir",
  "script" : "ls -l /",
  "targets" : [ "Management_Service" ]
})
if response is None:
    print("fehlschlag")
else:
    print(response)
    mydict = response.as_dict()
    print (mydict)
    mystr=mydict['data']['tasks'][0]['task-details'][0]['responseMessage']

    pprint.pprint (mydict['data']['tasks'][0]['task-details'][0]['responseMessage'])
    print (base64.b64decode(mystr))
client.logout()