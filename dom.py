import CP
import pprint
import credentials


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password


client=CP.CP(ipaddr,username, password)
def print_dict(dict):
    for key in dict:
        print(key,mydict[key][0])



if client==-1:
    print ("Login failed")
    exit(1)
domains = client.call_api("show-domains")
print (domains)
client.get_policy_packages()
client.logout()
