import CP
import pprint 
import base64

#print("##################################################################")
client=CP.CP("192.168.173.81","admin","admin123")
if client==-1:
    print ("Login failed")
    exit(1)
layers = client.call_api("show-access-layers")
pp=client.get_policy_packages()
print (pp)
item={"name": "Network", "details-level": "standard", "use-object-dictionary": "false" ,"show-hits": "true","limit":500,"offset":0}
response=client.call_api("show-access-rulebase",item)
if response.success:
    #print (len(response['data]))
    mydict = response.res_obj['data']
           
       
    #num=len(list_of_rules)
    #print (list_of_rules[0])
    #rules=mydict['rulebase']
    #print (rules)
    print(mydict['name']) # list
    print(mydict)
    pprint.pprint(mydict)
    sections=(len(mydict['rulebase'])) # How much sections
    i=1
    for x in range (sections):
        print (mydict['rulebase'][x]) # section name
        section_rules=mydict['rulebase'][x]
        section_name=mydict['rulebase'][x]
    #pprint.pprint(mydict)
        
        for item in section_rules:
                print ("### Rule {} in {} ###".format(i,section_name))
                #print (item)
                #print(item['name'])
                print("Enabled {}".format(item['enabled']))
                print(item['uid'])
                if (item['enabled']==False):
                    print ("Rule {} disabled".format(item['uid']))
                i+=1
        
    
    #print (mydict)
    #print (response)
client.logout()
