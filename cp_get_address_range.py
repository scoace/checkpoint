import CP
import pprint
import base64


client = CP.CP("192.168.173.87", "admin", "admin123")

# print (response.data['responseMessage'])
response = client.call_api(
    "show-address-ranges", {"limit": 50, "offset": 0, "details-level": "standard"}
)
mydict = response.as_dict()
# print (mydict)
obj_list = mydict["data"]["objects"]
print(obj_list)
print("TCP Services: Name Port UID")
for item in obj_list:
    print(item['name'],item['ipv4-address-first'], item['ipv4-address-last'])
    

# get task-id

#pprint.pprint(response)
client.logout()
