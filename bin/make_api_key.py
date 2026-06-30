#!/usr/bin/env python3

import hashlib
import pathlib
import uuid
import sys

# Generate a secure API key
api_key = "tk-" + str(uuid.uuid4())

# Also create a sha256 sum of the key that can be added to the apikeys file
hash_b = hashlib.sha256(api_key.encode())

# Print the key and sha256 for copy-pasting convenience
print("API Key: %r" % api_key)
print(f"sha256:{hash_b.hexdigest()}")


if len(sys.argv) > 1:
    # Write the key to a file. We don't write the digest to a
    # file because it needs to be added to the apikeys yaml file
    outfile = pathlib.Path(sys.argv[1])
    outfile.write_text(api_key)
else:
    sys.exit(f"Usage: {sys.argv[0]} <keyfile>")
