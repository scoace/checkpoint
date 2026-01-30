import CP
import pprint 
import base64
import credentials


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password


client=CP.CP(ipaddr,username, password)

hosts=client.get_hosts()

for host in hosts:
    pprint.pprint (host)
    print("-----------------------------------------------------------------")