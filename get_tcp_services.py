import CP
import pprint 
import base64
import credentials
import json


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

def extract_name_port_color(data):
    """
    Extract name, port, and color from the JSON data
    
    Args:
        data (dict): The JSON dictionary
        
    Returns:
        tuple: (name, port, color) or None if any field is missing
    """
    
    # Check if all required fields exist
    required_fields = ['name', 'port', 'color']
    for field in required_fields:
        if field not in data:
            print(f"Warning: Missing required field '{field}'")
            return None
    
    name = data['name']
    port = data['port']
    color = data['color']
    
    return (name, port, color)


def extract_fields(data):
    """
    Extract name, port, domain.name, and color from the JSON data
    
    Args:
        data (dict): The JSON dictionary
        
    Returns:
        tuple: (name, port, domain_name, color) or None if any field is missing
    """
    
    # Check if all required fields exist
    required_fields = ['name', 'port', 'domain', 'color']
    for field in required_fields:
        if field not in data:
            print(f"Warning: Missing required field '{field}'")
            return None
    
    # Extract the values
    name = data['name']
    port = data['port']
    color = data['color']
    
    # Extract domain name from nested domain object
    if isinstance(data['domain'], dict) and 'name' in data['domain']:
        domain_name = data['domain']['name']
    else:
        print("Warning: Could not extract domain.name")
        return None
    
    return (name, port, domain_name, color)


client=CP.CP(ipaddr,username=username, password=password)

tcp_services=client.get_tcp_services_dict()
test=client.get_services_tcp()

#for service in tcp_services:
#    pprint.pprint (service)
#    print("-----------------------------------------------------------------")
offset=0
#extract_name_port(tcp_services)
response = client.call_api(
                "show-services-tcp",
                {"limit": 500, "offset": offset, "details-level": "standard"},
            )
if response.success:
    #print (response)
    mydict = response.as_dict()
    tcp_services = mydict["res_obj"]["data"]["objects"]
    for item in tcp_services:
        result = extract_fields(item)
        if result:
            name, port, domain_name, color = result
        
        
            # You can also format it as a string
            if (domain_name=="SMC User"):
                formatted_output = f"Service: {name}, Port: {port}, Domain-Name: {domain_name},Color: {color}"
                print(f"\nFormatted output: {formatted_output}")
        else:
            print("Could not extract all required fields")
        
    #print (tmp_list_of_services[0])

with open("tcp_services.json", "w", encoding="utf-8") as f:
    json.dump(tcp_services, f, ensure_ascii=False, indent=2)
