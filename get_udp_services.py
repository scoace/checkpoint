import CP
import pprint 
import base64
import credentials
import json


ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

def extract_name_port(data):
    """
    Extract name and port from JSON data
    
    Args:
        data (str or dict): JSON string or parsed dictionary
    """
    
    # If data is a string, parse it as JSON
    if isinstance(data, str):
        try:
            parsed_data = json.loads(data)
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            return
    else:
        parsed_data = data
    
    # Iterate through the data and extract name and port
    for key, value_list in parsed_data.items():
        if isinstance(value_list, list):
            for item in value_list:
                if isinstance(item, dict) and 'name' in item and 'port' in item:
                    print(f"Name: {item['name']}, Port: {item['port']}")


client=CP.CP(ipaddr,username=username, password=password)

udp_services=client.get_udp_services_dict()

#for service in udp_services:
#    pprint.pprint (service)
#    print("-----------------------------------------------------------------")
extract_name_port(udp_services)

with open("udp_services.json", "w", encoding="utf-8") as f:
    json.dump(udp_services, f, ensure_ascii=False, indent=2)
