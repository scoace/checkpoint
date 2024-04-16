import CP
import pprint

def print_dict(dict):
    for key in dict:
        print(key,mydict[key][0])


client=CP.CP("10.120.120.10","admin","admin123")
if client==-1:
    print ("Login failed")
    exit(1)
domains = client.call_api("show-domains")
print (domains)
client.get_policy_packages()
client.logout()
client=CP.CP("10.120.120.10","admin","admin123","tch02")
if client==-1:
    print ("Login failed")
    exit(1)
domains = client.call_api("show-domains")
print (domains)
packages=client.get_policy_packages()
for item in packages:
    print (item['name'])
mydict=client.get_host_dict()
#print_dict(mydict)
client.add_service_tcp("tcp_8081","8081")
client.commit()
client.logout()

for item in mydict:
    print (item,mydict[item])