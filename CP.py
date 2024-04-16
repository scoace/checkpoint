#
# CP.py
# version 0.1
#
#
# Wrapper for cpapi
#
#
#
#
# written by: aaust@magellan-net.de
# March 2020
#

from __future__ import print_function

# A package for reading passwords without displaying them on the console.
import getpass

import sys, os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs


class CP:
    """Wrapper for APIClientArgs, APIClient
    Parameter: ip-addr mgmgt, username, password, optional domain,port
    """

    def __init__(self, ipaddr, username, password, domain=None, port="443"):

        self.api_server = ipaddr
        self.username = username
        self.password = password
        self.port = port
        # self.urlbase = "https://{ipaddr}:{port}/".format(ipaddr=self.ipaddr,port=self.port)
        # self.timeout = timeout
        if domain:
            self.domain = domain
        client_args = APIClientArgs(server=self.api_server, port=self.port)
        self.client = APIClient(client_args)
        if self.client.check_fingerprint() is False:
            print(
                "Could not get the server's fingerprint - Check connectivity with the server."
            )
            exit(1)

        # login to server:
        if domain:
            login_res = self.client.login(
                self.username, self.password, False, self.domain
            )
        else:
            login_res = self.client.login(self.username, self.password)

        if login_res.success is False:
            print(f"Login failed:\n{login_res.error_message}")
            exit(1)

    # getting details from the user

    def add_rule(self, mydict):
        """add rule
        Parameter: name, payload
        """

        # add a rule to the top of the "Network" layer
        # add_rule_response = self.client.api_call("add-access-rule",
        #                                            {"name": rule_name, "layer": "Network", "position": "top"})
        response = self.client.api_call("add-access-rule", mydict)
        if response.success:

            print(f"The rule: '{mydict['name']}' has been added successfully")
            return response
        else:
            return -1

    def get_hosts(self):
        """get hosts
        parameter: none
        returns list of hosts
        """

        list_of_hosts = []
        for x in range(100):  # max 5000 hosts

            offset = x * 500
            response = self.client.api_call(
                "show-hosts",
                {"limit": 500, "offset": offset, "details-level": "standard"},
            )

            # pprint.pprint(response)
            if response.success:
                # print (len(response.as_dict()))
                mydict = response.as_dict()

                tmp_list_of_hosts = mydict["data"]["objects"]
                list_of_hosts = list_of_hosts + tmp_list_of_hosts
                counthosts = len(tmp_list_of_hosts)
                if counthosts < 500:
                    break
        return list_of_hosts

    def add_host(self, name, ipaddr):
        """add host
        Parameter: name, ipaddr
        """

        response = self.client.api_call(
            "add-host",
            {
                "name": name,
                "ip-address": ipaddr,
                "set-if-exists": True,
                "ignore-warnings": True,
            },
        )

        # pprint.pprint(response)
        if response.success:
            # print (len(response.as_dict()))
            print(f"host: {name} added successfull")
            return 0
        else:
            return -1

    def add_network(self, name, subnet, subnetmask):
        """add netork object
        Parameter: name, subnet, subnetmask
        """

        response = self.client.api_call(
            "add-network", {"name": name, "subnet": subnet, "subnet-mask": subnetmask}
        )
        # pprint.pprint(response)
        if response.success:
            # print (len(response.as_dict()))
            print(f"network: {name} added successful")
            return 0
        else:
            return -1

    def add_service_tcp(self, name, port):
        """add service tcp
        Parameter: name,port
        """

        response = self.client.api_call(
            "add-service-tcp",
            {
                "name": name,
                "port": port,
                "set-if-exists": False,
                "match-for-any": False,
            },
        )

        # pprint.pprint(response)
        if response.success:
            # print (len(response.as_dict()))
            print(f"service: {name} added successfull")
            return 0
        else:
            return -1

    def add_service_udp(self, name, port):
        """add service udp
        Parameter: name,port
        """

        response = self.client.api_call(
            "add-service-udp",
            {
                "name": name,
                "port": port,
                "set-if-exists": False,
                "match-for-any": False,
            },
        )

        # pprint.pprint(response)
        if response.success:
            # print (len(response.as_dict()))
            print(f"service: {name} added successfull")
            return 0
        else:
            return -1

    def get_networks(self):
        """returns list of networks"""
        list_of_networks = []
        for x in range(100):  # max 5000 hosts

            offset = x * 500
            response = self.client.api_call(
                "show-networks",
                {"limit": 500, "offset": offset, "details-level": "standard"},
            )

            # pprint.pprint(response)
            if response.success:
                # print (len(response.as_dict()))
                mydict = response.as_dict()
                num_networks = mydict["data"]["total"]
                # print (mydict)
                tmp_list_of_networks = mydict["res_obj"]["data"]["objects"]
                list_of_networks = list_of_networks + tmp_list_of_networks
                count = len(tmp_list_of_networks)
                if count < 500:
                    break
        return list_of_networks

    def get_services_tcp(self):
        """returns list of tcp services"""
        list_of_services = []

        for x in range(100):  # max 5000 hosts

            offset = x * 500
            response = self.client.api_call(
                "show-services-tcp",
                {"limit": 500, "offset": offset, "details-level": "standard"},
            )

            # pprint.pprint(response)
            if response.success:
                # print (len(response.as_dict()))
                mydict = response.as_dict()
                num_networks = mydict["data"]["total"]
                # print (mydict)
                tmp_list_of_services = mydict["res_obj"]["data"]["objects"]
                list_of_services = list_of_services + tmp_list_of_services
                count = len(tmp_list_of_services)
                if count < 500:
                    break
        return list_of_services

    def get_services_udp(self):
        """returns list of udp services"""

        list_of_services = []

        for x in range(100):  # max 50000

            offset = x * 500
            response = self.client.api_call(
                "show-services-udp",
                {"limit": 500, "offset": offset, "details-level": "standard"},
            )

            # pprint.pprint(response)
            if response.success:
                # print (len(response.as_dict()))
                mydict = response.as_dict()
                num_networks = mydict["data"]["total"]
                # print (mydict)
                tmp_list_of_services = mydict["res_obj"]["data"]["objects"]
                list_of_services = list_of_services + tmp_list_of_services
                count = len(tmp_list_of_services)
                if count < 500:
                    break
        return list_of_services

    def get_policy_packages(self):
        """POST {{server}}/show-packages
        Content-Type: application/json
        X-chkp-sid: {{session}}

        {
        "limit" : 50,
        "offset" : 0,
        "details-level" : "standard"
        }
        returns list of policy packages
        """
        response = self.client.api_call(
            "show-packages", {"limit": 50, "offset": 0, "details-level": "standard"}
        )
        if response.success:
            # print (len(response.as_dict()))
            mydict = response.as_dict()
            return mydict["res_obj"]["data"]["packages"]

    def commit(self):
        """commit changes on management"""

        response = self.client.api_call("publish", {})
        if response.success:
            print("The changes were published successfully.")
            return 0
        else:
            print("Failed to publish the changes.")
            return -1

    def call_api(self, call, item=None):
        """Wrapper for api_call
        callname e.g add-host
        payload e.g {"name":"test123", "ip-address": "1.2.3.4"}
        """

        if item is None:
            response = self.client.api_call(call)
        else:
            response = self.client.api_call(call, item)
        if response.success:
            print("The call was successful.")
            return response
        else:
            print("The call failed")

    def logout(self):
        """logout of management"""
        response = self.client.api_call("logout")
        if response.success:
            print("Logout was successful.")
            return 0
        else:
            print("Logout failed")
            return -1

    def get_host_dict(self):
        """returns dictionary of hosts, index is IP-Address"""
        mylist = self.get_hosts()

        obj_dictionary = {}

        for host in mylist:
            ipaddr = host.get("ipv4-address")
            if ipaddr is None:
                print(host["name"] + " has no IPv4 address. Skipping...")
                continue
            host_data = {"name": host["name"], "uid": host["uid"]}
            if ipaddr in obj_dictionary:

                obj_dictionary[ipaddr] += [host_data]  # '+=' modifies the list in place
            else:
                obj_dictionary[ipaddr] = [host_data]
        return obj_dictionary

    def get_network_dict(self):
        """returns dictionary of networks, index is subnet"""

        obj_dictionary = {}

        mylist = self.get_networks()

        for network in mylist:
            subnet = network.get("subnet4")
            if subnet is None:
                continue
            else:
                netmask = network.get("subnet-mask")
            network_data = {
                "name": network["name"],
                "uid": network["uid"],
                "subnet4": network["subnet4"],
                "subnet-mask": network["subnet-mask"],
            }
            if subnet in obj_dictionary:
                obj_dictionary[subnet] += [network_data]
            else:
                obj_dictionary[subnet] = [network_data]
        return obj_dictionary

    def get_tcp_services_dict(self):
        """returns dictionary of tcp services, index is Name"""

        obj_dictionary = {}

        mylist = self.get_services_tcp()
        """ {'uid': '24de2cde-dfcd-4c9b-9124-492ac4bedba7', 'name': 'Xanadu', 'type': 'service-tcp', 'domain': {'uid': 'a0bbbc99-adef-4ef8-bb6d-defdefdefdef', 'name': 'Check Point Data', 
        'domain-type': 'data domain'}, 'port': '1031'} """
        for service in mylist:
            port = service.get("port")
            name = service.get("name")
            if port is None:
                continue

            service_data = {
                "name": service["name"],
                "uid": service["uid"],
                "port": service["port"],
            }
            if name in obj_dictionary:
                obj_dictionary[name] += [service_data]
            else:
                obj_dictionary[name] = [service_data]
        return obj_dictionary

    def get_udp_services_dict(self):
        """returns dictionary of udp services, index is Name"""

        obj_dictionary = {}

        mylist = self.get_services_udp()
        """ {'uid': '24de2cde-dfcd-4c9b-9124-492ac4bedba7', 'name': 'Xanadu', 'type': 'service-tcp', 'domain': {'uid': 'a0bbbc99-adef-4ef8-bb6d-defdefdefdef', 'name': 'Check Point Data', 
        'domain-type': 'data domain'}, 'port': '1031'} """
        for service in mylist:
            port = service.get("port")
            name = service.get("name")
            if port is None:
                continue

            service_data = {
                "name": service["name"],
                "uid": service["uid"],
                "port": service["port"],
            }
            if name in obj_dictionary:
                obj_dictionary[name] += [service_data]
            else:
                obj_dictionary[name] = [service_data]
        return obj_dictionary
