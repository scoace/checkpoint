import CP


client=CP.CP("192.168.173.81","admin","admin123")


mydict=client.get_host_dict()

for item in mydict:
    print (mydict[item])

mydict=client.get_policy_packages()

for item in mydict:
    print (item['name'])


response=client.call_api("export",{"export-files-by-class" : True} )
print (response)
client.logout()