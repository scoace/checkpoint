import CP
import pprint
import base64


list_of_hosts = []
list_of_networks = []
list_of_services = []

# print("##################################################################")
client = CP.CP("192.168.173.87", "admin", "admin123")
if client == -1:
    print("Login failed")
    exit(1)

obj_dictionary = client.get_host_dict()  # dict of hosts, key is IP

# for item in obj_dictionary:
print("Hosts: IP Name UID")
for key, value in obj_dictionary.items():
    print(key, value[0]["name"], value[0]["uid"])

obj_dictionary = client.get_tcp_services_dict()  # dict of tcp_services, key is Name
#pprint.pprint(obj_dictionary)
print("TCP Services: Name Port UID")
for key, value in obj_dictionary.items():
    print(key, value[0]["port"], value[0]["uid"])