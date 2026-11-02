from checkpoint_api import CheckPointAPI
import pandas as pd
import json

with CheckPointAPI(
    "10.8.146.3",
    username="admin",
    password="admin123",
) as client:
    data = client.api_call("show-hosts", {"limit": 50})
    print(data)



# Extract the list of hosts from the data
hosts = data["objects"]

# Create a DataFrame
df = pd.DataFrame(hosts)
print (df)
# Flatten nested dictionaries (like domain)
#df = df.join(pd.json_normalize(df['domain']))

# Remove the original 'domain' column since we've flattened it
#df.drop(columns=['domain'], inplace=True)

# Save to CSV file
df.to_csv('hosts.csv', index=False)

# Display first few rows of the DataFrame
print(df.head())