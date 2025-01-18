1. ```cd ~ && apt install build-essentials -y && git clone https://github.com/edthepurple/auth-script-openvpn```
2. ```cd auth-script-openvpn```
3. ```make```
4. ```mv openvpn-plugin-auth-script.so /usr/local/lib/openvpn/plugins```
5. edit openvpn server configuration and place this there

   ```plugin /usr/local/lib/openvpn/plugins/openvpn-auth-script.so /etc/openvpn/scripts/login.sh```

6. your login script can be something like this


```bash
#!/bin/bash

AUTH_SUCCESS="1"
AUTH_FAILURE="0"

# Function to write the value to the control file and exit
respond_with() {
  value=$1
  control_path=$2
  echo "$value" > "$control_path"
  exit 0
}

# Read the username and password from the environment variables passed by OpenVPN
username=$username
password=$password

# Read the auth_control_file from the environment variable passed by OpenVPN
auth_control_file=$auth_control_file

# API authentication endpoint
AUTH_URL="https://api.chacha20.com/login.php"

# Make the HTTP request to authenticate the user
response=$(curl -s "${AUTH_URL}?username=${username}&password=${password}")

# Parse the JSON response to extract the status field
status=$(echo "$response" | jq -r '.status')

# Check if the status is "success"
if [ "$status" == "success" ]; then
  respond_with "$AUTH_SUCCESS" "$auth_control_file"
else
  respond_with "$AUTH_FAILURE" "$auth_control_file"
fi
```
note: make sure you have jq installed. on ubuntu use ```apt install jq -y``` to install it.

**ENJOY**
