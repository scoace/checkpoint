#!/usr/bin/env python3
"""
Script to read tcp.json and add tcp using CP class
"""

import json
import sys
import os
#import credentials

ipaddr=credentials.ipaddr
username=credentials.username
password=credentials.password

# Try to import the CP class - this might need adjustment based on actual CP.py structure
try:
    # If CP.py is in the same directory, we can import it directly
    from CP import CP
except ImportError:
    # If that fails, try to handle it gracefully
    print("Warning: Could not import CP class. Make sure CP.py is in the same directory.")
    sys.exit(1)

def read_tcp_json(file_path):
    """
    Read tcp data from JSON file
    
    Args:
        file_path (str): Path to tcp.json file
        
    Returns:
        list: List of host dictionaries
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # Handle different JSON structures
        if isinstance(data, dict):
            # If it's a dictionary with tcp as keys or a "tcp" key
            if 'tcp' in data and isinstance(data['tcp'], list):
                return data['tcp']
            else:
                # Return the entire dict as a single host entry (assuming it's one host)
                return [data]
        elif isinstance(data, list):
            # If it's already a list of tcp
            return data
        else:
            print(f"Unexpected JSON structure: {type(data)}")
            return []
            
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found!")
        return []
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{file_path}': {e}")
        return []

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

def main():
    """Main function to process tcp and add them"""
    
    # Check if tcp.json exists
    tcp_file = "tcp_services.json"
    if not os.path.exists(tcp_file):
        print(f"Error: {tcp_file} not found in current directory!")
        return 1
    
    # Read tcp from JSON file
    tcp_data = read_tcp_json(tcp_file)
    
    if not tcp_data:
        print("No tcp data to process")
        return 1
    
    # Initialize CP class (assuming it has proper initialization)
    try:
        client = CP(ipaddr=ip,username=user,password=password)
    except Exception as e:
        print(f"Error initializing CP class: {e}")
        return 1
    offset=0    
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
    
    
    
    #print (tcp_services)
    for item in tcp_services:
        #print (item)
        result = extract_fields(item)
        if result:
            name, port, domain_name, color = result
        
        
            # You can also format it as a string
            if (domain_name=="SMC User"):
                formatted_output = f"Service: {name}, Port: {port}, Domain-Name: {domain_name},Color: {color}"
                print(f"\nFormatted output: {formatted_output}")
                #response = client.call_api(
                #    "add-service-tcp",
                #    {"name": name, "port": port, "color": color},
                #)
                #if response.success:
                #    print(f"{formatted_output} successfull added")

        else:
            print("Could not extract all required fields")
    
    #client.commit()
    #return 0 if success_count == total_count else 1

if __name__ == "__main__":
    sys.exit(main())