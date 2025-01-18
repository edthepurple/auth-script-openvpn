1. cd ~ && git clone https://github.com/edthepurple/auth-script-openvpn
2. cd auth-script-openvpn
3. make
4. mv openvpn-plugin-auth-script.so /usr/local/lib/openvpn/plugins
5. edit openvpn server configuration and place this there

   plugin /usr/local/lib/openvpn/plugins/openvpn-auth-script.so /etc/openvpn/scripts/login.sh

6. your login script can be something like this

#!/bin/bash

AUTH_SUCCESS="1"
AUTH_FAILURE="0"

respond_with() {
  value=$1
  control_path=$2
  echo "$value" > "$control_path"
  exit 0
}

username=$username
password=$password

auth_control_file=$auth_control_file

AUTH_URL="https://api.chacha20.com/login.php"

response=$(curl -s "${AUTH_URL}?username=${username}&password=${password}")

status=$(echo "$response" | jq -r '.status')

if [ "$status" == "success" ]; then
  respond_with "$AUTH_SUCCESS" "$auth_control_file"
else
  respond_with "$AUTH_FAILURE" "$auth_control_file"
fi

**ENJOY**
