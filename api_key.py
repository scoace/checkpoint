import CP
import pprint 
import base64
import credentials # import ip, username, password

# Instance Class Object and login
ipaddr=credentials.ipaddr
api_key=credentials.api_key
client=CP.CP(ipaddr,username, password)

# Alternatively, login with API Key
client=CP.CP(ipaddr, api_key=API_KEY)

mylist=client.get_hosts()

for item in mylist:
    print (item['name'],item['ipv4-address'],item['color'])
    
mylist=client.get_networks()

for item in mylist:
    if 'subnet4' in item and item['subnet4']:
        print(item['name'], item['subnet4'], item['color'])

mydict=client.get_policy_packages()

for item in mydict:
    print (item['name'])
"""    
response=client.call_api("show-hosts",{
  "limit" : 50,
  "offset" : 0,
  "details-level" : "standard"
})
mydict = response.as_dict()
pprint.pprint(mydict)
"""
client.logout()
