import CP


client=CP.CP("10.120.120.10","andy","admin123")
if client==-1:
    print ("Login failed")
    exit(1)
domains = client.call_api("show-domains")
print (domains)
client.get_policy_packages()
client.logout()
client=CP.CP("10.120.120.10","andy","admin123","tch01")
if client==-1:
    print ("Login failed")
    exit(1)
domains = client.call_api("show-domains")
print (domains)
packages=client.get_policy_packages()
print (packages)
client.logout()