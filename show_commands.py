import CP
import pprint 
import base64
import credentials


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

client=CP.CP(ipaddr,username, password)
response=client.call_api("show-commands",{
  
})
mydict = response.as_dict()
print (mydict['data']['commands'])
for item in mydict['data']['commands']:
    print (item)