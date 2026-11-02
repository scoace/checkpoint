#!/usr/bin/env python3
"""
Script to read hosts.json and add hosts using CP class
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

def read_hosts_json(file_path):
    """
    Read hosts data from JSON file
    
    Args:
        file_path (str): Path to hosts.json file
        
    Returns:
        list: List of host dictionaries
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        
        # Handle different JSON structures
        if isinstance(data, dict):
            # If it's a dictionary with hosts as keys or a "hosts" key
            if 'hosts' in data and isinstance(data['hosts'], list):
                return data['hosts']
            else:
                # Return the entire dict as a single host entry (assuming it's one host)
                return [data]
        elif isinstance(data, list):
            # If it's already a list of hosts
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

def main():
    """Main function to process hosts and add them"""
    
    # Check if hosts.json exists
    hosts_file = "hosts.json"
    if not os.path.exists(hosts_file):
        print(f"Error: {hosts_file} not found in current directory!")
        return 1
    
    # Read hosts from JSON file
    hosts_data = read_hosts_json(hosts_file)
    
    if not hosts_data:
        print("No host data to process")
        return 1
    
    # Initialize CP class (assuming it has proper initialization)
    try:
        cp = CP(ipaddr=ip,username=user,password=password)
    except Exception as e:
        print(f"Error initializing CP class: {e}")
        return 1
    
    success_count = 0
    total_count = len(hosts_data)
    
    print(f"Processing {total_count} hosts...")
    
    # Process each host
    for i, host in enumerate(hosts_data):
        try:
            # Extract host information (handle different JSON structures)
            name = host.get('name') or host.get('host_name') or f"host_{i+1}"
            ipaddr = host.get('ipv4-address') or host.get('ip') or host.get('address')
            color = host.get('color', 'black')  # Default to black if no color specified
            print(f"Host: '{name}' ip: '{ipaddr}'")
            # Make sure we have required fields
            if not ipaddr:
                print(f"Warning: Skipping host '{name}' - missing IP address")
                continue
                
            print(f"Adding host: {name} ({ipaddr})")
            
            # Call add_host function
            result = cp.add_host(name, ipaddr, color)
            
            if result == 0:
                print(f"Successfully added host: {name}")
                success_count += 1
            else:
                print(f"Failed to add host: {name}")
                
        except Exception as e:
            print(f"Error processing host {i+1}: {e}")
            continue
    
    print(f"\nSummary: {success_count}/{total_count} hosts added successfully")
    cp.commit()
    return 0 if success_count == total_count else 1

if __name__ == "__main__":
    sys.exit(main())