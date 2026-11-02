import CP
import pprint
import base64
import credentials


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

print ("User: {} pass: {} ipaddr: {}".format(username,password,ipaddr))
client=CP.CP(ipaddr,username=username, password=password)

# print (response.data['responseMessage'])
response = client.call_api(
    "show-address-ranges", {"limit": 50, "offset": 0, "details-level": "standard"}
)
mydict = response.as_dict()
# print (mydict)
obj_list = mydict["data"]["objects"]
#print.(obj_list)
print("Address Ranges: Name Port UID")
for item in obj_list:
    print(item['name'],item['ipv4-address-first'], item['ipv4-address-last'])
    

# get task-id

#pprint.pprint(response)
client.logout()
