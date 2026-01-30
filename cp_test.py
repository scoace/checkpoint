import CP
import pprint 
import base64
import credentials


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password


client=CP.CP(ipaddr,username, password)



""" mydict=client.get_host_dict()

for item in mydict:
    print (mydict[item])

mydict=client.get_policy_packages()

for item in mydict:
    print (item['name']) """
    
    

response=client.call_api("run-script",{
  "script-name" : "Script Example: List files under / dir",
  "script" : "ls -l /",
  "targets" : [ "mgmt" ]
})
mydict = response.as_dict()
print (mydict)
mystr=mydict['data']['tasks'][0]['task-details'][0]['responseMessage']

pprint.pprint (mydict['data']['tasks'][0]['task-details'][0]['responseMessage'])
print (base64.b64decode(mystr))


#print (response.data['responseMessage'])
response=client.call_api("export",{"export-files-by-class" : True} )
mydict = response.as_dict()
mystr=mydict['data']['tasks'][0]['task-id']
pprint.pprint(mydict)
print (mystr)
#get task-id
response=client.call_api("show-task",{'task-id': mystr})
pprint.pprint(response)
client.logout()
