import CP
import pprint 
import base64
import credentials # import ip, username, password

ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

#client=CP.CP("192.168.173.81","admin","admin123")
client=CP.CP(ipaddr,username, password)

response=client.call_api("show-access-rulebase",{"name" : "Cluster_policy Network"})

pprint.pprint(response)

client.logout()
