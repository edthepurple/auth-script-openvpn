1. ```cd ~ && apt install build-essential -y && git clone https://github.com/edthepurple/auth-script-openvpn```
2. ```cd auth-script-openvpn```
3. ```make```
4. ```mv openvpn-plugin-auth-script.so /usr/local/lib/openvpn/plugins```
5. edit openvpn server configuration and place this there

   ```plugin /usr/local/lib/openvpn/plugins/openvpn-auth-script.so /etc/openvpn/scripts/login.sh```

6. your login script can be something like this


```bash
#!/bin/bash
#
# OpenVPN Authentication Script (Optimized)
# Validates user credentials against MySQL database with bcrypt
#

set -euo pipefail

readonly AUTH_SUCCESS="1"
readonly AUTH_FAILURE="0"

# Database connection details
readonly DB_HOST=""
readonly DB_USER=""
readonly DB_PASSWORD=""
readonly DB_NAME=""

# Common MySQL options
readonly MYSQL_OPTS="--host=${DB_HOST} --user=${DB_USER} --password=${DB_PASSWORD} --database=${DB_NAME}"

# Log function (writes to syslog since we're daemonized)
log_msg() {
    logger -t "openvpn-auth" "$1"
}

# Respond to OpenVPN and exit
respond_with() {
    local value="$1"
    local control_path="$2"
    
    if [[ -n "$control_path" && -w "$(dirname "$control_path")" ]]; then
        echo "$value" > "$control_path"
    fi
    exit 0
}

# Validate required environment variables
validate_env() {
    if [[ -z "${username:-}" ]]; then
        log_msg "ERROR: username not set"
        return 1
    fi
    
    if [[ -z "${password:-}" ]]; then
        log_msg "ERROR: password not set"
        return 1
    fi
    
    if [[ -z "${auth_control_file:-}" ]]; then
        log_msg "ERROR: auth_control_file not set"
        return 1
    fi
    
    return 0
}

# Escape string for safe MySQL usage (prevents SQL injection)
mysql_escape() {
    local str="$1"
    # Escape backslashes first, then single quotes
    str="${str//\\/\\\\}"
    str="${str//\'/\\\'}"
    echo "$str"
}

# Main authentication logic
main() {
    local auth_file="${auth_control_file:-}"
    
    # Validate environment
    if ! validate_env; then
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Escape username for SQL query (CRITICAL: prevents SQL injection)
    local safe_username
    safe_username=$(mysql_escape "$username")
    
    # Query user info from database
    local user_info
    if ! user_info=$(mysql $MYSQL_OPTS -s -N -e \
        "SELECT password, validity, unlimited FROM users WHERE BINARY username='${safe_username}' LIMIT 1;" 2>/dev/null); then
        log_msg "ERROR: Database query failed for user: $username"
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Check if user exists
    if [[ -z "$user_info" ]]; then
        log_msg "AUTH FAILED: User not found: $username"
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Parse results (handle potential whitespace issues)
    local hashed_password validity unlimited
    read -r hashed_password validity unlimited <<< "$user_info"
    
    # Remove any trailing carriage returns
    hashed_password="${hashed_password%$'\r'}"
    validity="${validity%$'\r'}"
    unlimited="${unlimited%$'\r'}"
    
    # Validate parsed values
    if [[ -z "$hashed_password" ]]; then
        log_msg "AUTH FAILED: No password hash for user: $username"
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Default values for validity check
    validity="${validity:-0}"
    unlimited="${unlimited:-0}"
    
    # Check account validity
    if [[ "$validity" -lt 0 && "$unlimited" -ne 1 ]]; then
        log_msg "AUTH FAILED: Account expired for user: $username"
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Verify password using bcrypt
    if ! /usr/bin/auth "$password" "$hashed_password" 2>/dev/null | grep -q "yes"; then
        log_msg "AUTH FAILED: Invalid password for user: $username"
        respond_with "$AUTH_FAILURE" "$auth_file"
    fi
    
    # Authentication successful - update last login
    local safe_username_update
    safe_username_update=$(mysql_escape "$username")
    
    if ! mysql $MYSQL_OPTS -e \
        "UPDATE users SET lastlogin=NOW() WHERE username='${safe_username_update}';" 2>/dev/null; then
        # Log but don't fail auth if update fails
        log_msg "WARNING: Failed to update lastlogin for user: $username"
    fi
    
    log_msg "AUTH SUCCESS: User authenticated: $username"
    respond_with "$AUTH_SUCCESS" "$auth_file"
}

# Run main function
main
```
note: make sure you have jq installed. on ubuntu use ```apt install jq -y``` to install it.

**ENJOY**
