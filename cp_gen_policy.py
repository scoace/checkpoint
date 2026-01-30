import csv
import re
import socket
import struct
import cpapi
import CP
import credentials # import ip, username, password

# Instance Class Object and login
ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password
client=CP.CP(ipaddr,username, password)

tufin = "y:/checkpoint/checkpoint/Last_policy.csv"
Policy_Package = "ISFW_new"


def cidr_to_netmask(cidr):
    network, net_bits = cidr.split("/")
    host_bits = 32 - int(net_bits)
    netmask = socket.inet_ntoa(struct.pack("!I", (1 << 32) - (1 << host_bits)))
    return network, netmask


def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count("1") for x in netmask.split(".")])


list_of_hosts = []
list_of_networks = []
list_of_services = []
# Open Secure Track csv and parse lines for src, dst, services
with open(tufin, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    for row in reader:
        # print(row[0],row[2])
        if row:
            if re.match("Rule", (row[0])):
                # print (row)
                # print (row [1], row[2], row [3], row[4])
                # Generate SRC Addresslist
                if row[1] != "Any":
                    ip, nm = cidr_to_netmask(row[1])
                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                    if nm == "255.255.255.255":
                        name = "h_" + ip
                        mylist = [name, ip]
                        if mylist not in list_of_hosts:
                            list_of_hosts.append(mylist)
                    else:
                        name = "n_" + ip
                        mylist = [name, ip, nm]
                        if mylist not in list_of_networks:
                            list_of_networks.append(mylist)
                # Generate DST Addresslist
                if row[2] != "Any":
                    ip, nm = cidr_to_netmask(row[2])
                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                    if nm == "255.255.255.255":
                        name = "h_" + ip
                        mylist = [name, ip]
                        if mylist not in list_of_hosts:
                            list_of_hosts.append(mylist)
                    else:
                        name = "n_" + ip
                        mylist = [name, ip, nm]
                        if mylist not in list_of_networks:
                            list_of_networks.append(mylist)
                # Generate Services List
                if row[4] != "Any":

                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                    name = row[4] + "_" + row[3]

                    mylist = [name, row[3], row[4]]
                    if mylist not in list_of_services:
                        list_of_services.append(mylist)






# Check for duplicate IP Object

obj_dictionary = cp.get_host_dict()  # dict of hosts, key is IP


for item in list_of_hosts:
    # print (item[1])
    if item[1] in obj_dictionary:
        print("IP: {} already exist as {}".format(item[1], obj_dictionary[item[1]]))
    else:
        cp.add_host(item[0], item[1])


# Check for duplicate Network Object
obj_dictionary = cp.get_network_dict()

for item in list_of_networks:
    if item[1] in obj_dictionary:
        # print (obj_dictionary[item[1]][0]['subnet-mask'])
        # print (item[2])
        if item[2] == obj_dictionary[item[1]][0]["subnet-mask"]:

            print(
                "Subnet: {} already exists as {}".format(item, obj_dictionary[item[1]])
            )
    else:
        cp.add_network(item[0], item[1], item[2])

# generate tcp and udp list from services list
list_of_tcp_services = []
list_of_udp_services = []

for item in list_of_services:
    print(item[2])
    if item[2] == "TCP":
        list_of_tcp_services.append(item)
    if item[2] == "UDP":
        list_of_udp_services.append(item)

# check if tcp service exists, if not add ist to database
obj_dictionary = cp.get_tcp_services_dict()
# d = {'1': 'one', '3': 'three', '2': 'two', '5': 'five', '4': 'four'}
# 'one' in d.values()
for item in list_of_tcp_services:
    # print (item[1])
    for objects in obj_dictionary:
        if item[1] == obj_dictionary[objects][0]["port"]:
            found = True
            # print (item,obj_dictionary[objects][0]['port'])
            break
    if found:
        print(
            item, obj_dictionary[objects][0]["name"], obj_dictionary[objects][0]["port"]
        )
        found = False
    else:
        print("Add service {}".format(item[1]))
        cp.add_service_tcp(item[0], item[1])

obj_dictionary = cp.get_udp_services_dict()

for item in list_of_udp_services:
    # print (item[1])
    for objects in obj_dictionary:
        if item[1] == obj_dictionary[objects][0]["port"]:
            found = True
            # print (item,obj_dictionary[objects][0]['port'])
            break
    if found:
        print(
            item, obj_dictionary[objects][0]["name"], obj_dictionary[objects][0]["port"]
        )
        found = False
    else:
        print("Add service {}".format(item[1]))
        cp.add_service_udp(item[0], item[1])

# Check for duplicate UDP port
# Todo

# End of object generation

# Generate Policy Package
mydict = {
    "name": Policy_Package,
    "comments": "Test",
    "color": "green",
    "threat-prevention": False,
    "access": True,
}

response = cp.call_api("add-package", mydict)
if response.success:
    print("New_Standard_Package_1 added")
# Generate Rules

net_dictionary = cp.get_network_dict()
host_dictionary = cp.get_host_dict()
tcp_dictionary = cp.get_tcp_services_dict()
udp_dictionary = cp.get_udp_services_dict()
comment = ""

# Open csv and generate rules
print("rulebase generation")
with open(tufin, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    position = 1
    for row in reader:
        # print(row[0],row[2])
        if row:
            if re.match("Rule", (row[0])):
                # print (row)
                # print (row [1], row[2], row [3], row[4])
                # Generate SRC Addresslist
                if row[1] != "Any":
                    ip, nm = cidr_to_netmask(row[1])
                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                    if nm == "255.255.255.255":
                        src = host_dictionary[ip][0]["uid"]
                    else:
                        src = net_dictionary[ip][0]["uid"]
                else:
                    src = "97aeb369-9aea-11d5-bd16-0090272ccb30"
                # Generate DST Addresslist
                if row[2] != "Any":
                    ip, nm = cidr_to_netmask(row[2])
                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                    if nm == "255.255.255.255":
                        dst = host_dictionary[ip][0]["uid"]
                    else:
                        dst = net_dictionary[ip][0]["uid"]
                else:
                    dst = "97aeb369-9aea-11d5-bd16-0090272ccb30"
                # Generate Services List

                if row[4] == "TCP":
                    for k in tcp_dictionary:
                        if tcp_dictionary[k][0]["port"] == row[3]:
                            # print (k,tcp_dictionary[k][0]['port'])
                            service = tcp_dictionary[k][0]["uid"]
                            comment = row[4] + "_" + row[3]
                            break
                        else:
                            service = "Any"
                            comment = row[4] + "_" + row[3]

                elif row[4] == "UDP":
                    for k in udp_dictionary:
                        if udp_dictionary[k][0]["port"] == row[3]:
                            # print (k,udp_dictionary[k][0]['port'])
                            service = udp_dictionary[k][0]["uid"]
                            comment = row[4] + "_" + row[3]
                            break
                        else:
                            service = "Any"
                            comment = row[4] + "_" + row[3]
                    # print ("ip: {} netmask: {}".format(ip,nm))
                    # Falls Host
                elif row[4] == "Any":
                    service = "Any"
                    comment = "Any"

                else:
                    service = "Any"
                    comment = row[4]
                PP = Policy_Package + " Network"
                mydict = {
                    "name": row[0],
                    "layer": PP,
                    "position": position,
                    "action": "accept",
                    "track": {"type": "Log"},
                    "source": [src],
                    "destination": [dst],
                    "service": service,
                    "comments": comment,
                }
                response = cp.call_api("add-access-rule", mydict)
                if response.success:
                    print(
                        "The rule: '{}' has been added successfully".format(
                            mydict["name"]
                        )
                    )
                    # print ("name: {} src: {} dst: {} srv: {} comment: {}".format(row[0],src,dst,service,comment))
                    position += 1
                else:
                    print("Error adding rule {}".format(row[0]))


# publish changes
cp.commit()
# logout
cp.logout()
