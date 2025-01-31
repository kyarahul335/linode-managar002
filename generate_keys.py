import json
import uuid

# Generate 10 unique keys (you can change this number)
keys = {}
for i in range(10):  # Generate 10 keys for example
    key = str(uuid.uuid4())  # Create a unique key
    keys[key] = None  # Initially, no token is associated with the key

# Save the keys to a file
with open("keys.json", "w") as file:
    json.dump(keys, file, indent=4)

print("Keys generated and saved to keys.json")