import CP
import pprint 
import base64

#API_KEY='YYqwcAfaLm4nGNrs2Z4Umg\\=\\='
API_KEY=r'YYqwcAfaLm4nGNrs2Z4Umg=='
client=CP.CP("192.168.173.90", api_key=API_KEY)

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
