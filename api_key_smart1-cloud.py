#
# add_group_with_api_key.py
# version 1.0
#
#
# This example demonstrates communication with Check Point Management server using Management API Library in Python.
# Login with api-key, and adding a group.
# The demonstrated commands are:
#
#   1. login with api-key
#   2. adding a group
#   3. publishing the changes
#
# Logout command is called automatically after the work with Management API Library is completed.
#

from __future__ import print_function

# A package for reading passwords without displaying them on the console.
import json

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# cpapi is a library that handles the communication with the Check Point management server.
from cpapi import APIClient, APIClientArgs
import credentials


def main():
    # getting details from the user
    #api_server = input("Enter server IP address or hostname:")
    api_server=credentials.ipaddr
    api_key=credentials.api_key
    cloud_mgmt=credentials.cloud_mgmt_id

    client_args = APIClientArgs(server=api_server,cloud_mgmt_id=cloud_mgmt)

    with APIClient(client_args) as client:

        
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        # login to server:
        login_res = client.login_with_api_key(api_key)

        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)

        # add the group
        add_group_response = client.api_call("show-hosts")

        if add_group_response.success:

            print(add_group_response)
            print(json.dumps([object]))
            # publish the result
            
        else:
            print("Failed to add the group: '{}', Error:\n{}".format(group_name, add_group_response.error_message))


if __name__ == "__main__":
    main()