#!/usr/bin/env python3
"""
Script to convert JSON file to CSV file
"""

import json
import csv
import sys
import os

def json_to_csv(json_file_path, csv_file_path=None):
    """
    Convert JSON file to CSV file
    
    Args:
        json_file_path (str): Path to the input JSON file
        csv_file_path (str): Path to the output CSV file (optional)
    
    Returns:
        bool: True if conversion successful, False otherwise
    """
    
    # Check if input file exists
    if not os.path.exists(json_file_path):
        print(f"Error: Input file '{json_file_path}' does not exist!")
        return False
    
    # Determine output file name if not provided
    if csv_file_path is None:
        base_name = os.path.splitext(json_file_path)[0]
        csv_file_path = f"{base_name}.csv"
    
    try:
        # Read JSON file
        with open(json_file_path, 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
        
        # Handle different JSON structures
        if isinstance(data, list):
            # If it's a list of objects
            if len(data) > 0 and isinstance(data[0], dict):
                # Get all unique keys from all dictionaries
                all_keys = set()
                for item in data:
                    if isinstance(item, dict):
                        all_keys.update(item.keys())
                
                # Sort keys for consistent column order
                all_keys = sorted(list(all_keys))
                
                # Write to CSV
                with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
                    writer = csv.DictWriter(csv_file, fieldnames=all_keys)
                    writer.writeheader()
                    
                    for item in data:
                        if isinstance(item, dict):
                            writer.writerow(item)
                        else:
                            # If item is not a dict, write it as a row with one column
                            writer.writerow({'value': str(item)})
                
                print(f"Successfully converted '{json_file_path}' to '{csv_file_path}'")
                return True
            else:
                # If list contains non-dict items, convert each to a row
                with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
                    writer = csv.writer(csv_file)
                    for item in data:
                        writer.writerow([str(item)])
                
                print(f"Successfully converted '{json_file_path}' to '{csv_file_path}'")
                return True
        
        elif isinstance(data, dict):
            # If it's a single dictionary
            with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                # Write header
                writer.writerow(['Key', 'Value'])
                # Write key-value pairs
                for key, value in data.items():
                    writer.writerow([key, str(value)])
            
            print(f"Successfully converted '{json_file_path}' to '{csv_file_path}'")
            return True
        
        else:
            # For primitive values (string, number, etc.)
            with open(csv_file_path, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(['Value'])
                writer.writerow([str(data)])
            
            print(f"Successfully converted '{json_file_path}' to '{csv_file_path}'")
            return True
            
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON format in '{json_file_path}': {e}")
        return False
    except Exception as e:
        print(f"Error during conversion: {e}")
        return False

def main():
    """Main function to handle command line arguments"""
    
    if len(sys.argv) < 2:
        print("Usage: python json_to_csv.py <input_json_file> [output_csv_file]")
        print("Example: python json_to_csv.py data.json output.csv")
        return
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    success = json_to_csv(input_file, output_file)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()