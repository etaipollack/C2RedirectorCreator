import digitalocean
import argparse
import json
import time
import sys # For sys.exit

# Attempt to import paramiko and provide instructions if not found
try:
    import paramiko
except ImportError:
    # This global message is fine, or we can check specifically before create-c2-redirector
    print("Note: The 'paramiko' library is required for the 'create-c2-redirector' functionality.")
    print("You can install it using: pip install paramiko")
    # We don't exit here, as other commands might not need paramiko
    # paramiko will be checked again if 'create-c2-redirector' is called.

# --- Default values for create-c2-redirector ---
DEFAULT_DROPLET_NAME = "scripted-redirector"
DEFAULT_DROPLET_REGION = "nyc3"
DEFAULT_DROPLET_SIZE = "s-1vcpu-1gb" # Example: 1 GB RAM, 1 vCPU, 25 GB SSD
DEFAULT_DROPLET_IMAGE = "ubuntu-22-04-x64" # Example: Ubuntu 22.04 LTS
DEFAULT_SSH_USER = "root"

REDIRECTOR_SETUP_SCRIPT = """
sudo apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 update && \
sudo apt install apache2 -y && \
sudo a2enmod ssl rewrite proxy proxy_http proxy_connect && \
sudo systemctl restart apache2 && \
sudo a2dissite 000-default.conf && \
echo "Generating self-signed certificate for REDIRECTOR_IP_ADDRESS..." && \
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/apache-selfsigned.key \
  -out /etc/ssl/certs/apache-selfsigned.crt \
  -subj "/C=US/ST=New York/L=New York/O=My Test Lab/CN=REDIRECTOR_IP_ADDRESS" \
  -batch && \
echo "Creating Apache site configuration for REDIRECTOR_IP_ADDRESS..." && \
sudo bash -c 'cat << '\''EOF'\'' > /etc/apache2/sites-available/ip-redirector.conf
<VirtualHost *:80>
    ServerName REDIRECTOR_IP_ADDRESS
    RewriteEngine On
    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName REDIRECTOR_IP_ADDRESS
    RewriteEngine On

    # Add these lines to make Apache trust the backends (Slivers) self-signed cert
    SSLProxyVerify none
    SSLProxyEngine On            # Enable SSL for the proxy connection to the backend
    SSLProxyCheckPeerCN Off      # Do NOT check the Common Name in the backend cert
    SSLProxyCheckPeerName Off    # Do NOT check peer name (hostname matching)
    SSLProxyCheckPeerExpire Off  # Do NOT check certificate expiry

#    RewriteCond %{HTTP_USER_AGENT} "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0 CustomBeacon" [NC]

    RewriteCond %{REQUEST_URI} ^/$ [NC]

    ProxyPass        /  https://C2_IP_ADDRESS:443/  nocanon
    ProxyPassReverse /  https:/C2_IP_ADDRESS:443/

#    RewriteRule ^.*$ https://www.google.com/ [R=302,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/apache-selfsigned.crt
    SSLCertificateKeyFile /etc/ssl/private/apache-selfsigned.key

    SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDH+AESGCM:DH+AESGCM:RSA+AESGCM:!aNULL:!eNULL:!LOW:!RC4:!MD5:!DSS:!EXP:!PSK:!SRP:!CAMELLIA:!SEED
    SSLHonorCipherOrder on
    SSLCompression off
</VirtualHost>
EOF
' && \
echo "Enabling site and reloading Apache..." && \
sudo a2ensite ip-redirector.conf && \
sudo systemctl reload apache2 && \
echo "Apache status:" && \
sudo systemctl status apache2 && \
echo "Setup script finished."
""".strip()

# --- Existing functions (list_droplets, create_domain, etc.) remain unchanged ---
def list_droplets(manager):
    print("\n--- Droplets ---")
    droplets = manager.get_all_droplets()
    if droplets:
        for droplet in droplets:
            print(f"ID: {droplet.id}, Name: {droplet.name}, Status: {droplet.status}, IP: {droplet.ip_address}")
    else:
        print("No droplets found.")

def create_droplet(manager, name, region, size, image, ssh_keys=None):
    print("\n--- Creating Droplet ---")
    # Resolve SSH key identifiers to SSHKey objects
    resolved_ssh_keys = []
    if ssh_keys:
        for key_identifier in ssh_keys:
            try:
                key_obj = manager.get_ssh_key(key_identifier)
                resolved_ssh_keys.append(key_obj)
            except digitalocean.DataReadError:
                print(f"Warning: SSH key with identifier '{key_identifier}' not found. Skipping.")
        if not resolved_ssh_keys and ssh_keys: # If identifiers were provided but none resolved
             print("Error: No provided SSH keys could be resolved. Droplet creation might fail or be inaccessible via SSH.")
             # Depending on strictness, you might want to return or raise an error here
    
    new_droplet = digitalocean.Droplet(token=manager.token,
                                       name=name,
                                       region=region,
                                       size_slug=size,
                                       image=image,
                                       ssh_keys=resolved_ssh_keys or None, # API expects list of key objects or None
                                       backups=False) # Default backups to false, can be an arg
    new_droplet.create()
    print(f"Droplet '{name}' creation initiated. ID: {new_droplet.id}. Check DigitalOcean console or wait for script if applicable.")
    return new_droplet # Return the droplet object

def list_domains(manager):
    print("\n--- Domains ---")
    domains = manager.get_all_domains()
    if domains:
        for domain in domains:
            print(f"Name: {domain.name}, TTL: {domain.ttl}")
    else:
        print("No domains found.")

def create_domain(manager, domain_name):
    print("\n--- Creating Domain ---")
    new_domain = digitalocean.Domain(token=manager.token, name=domain_name)
    new_domain.create()
    print(f"Creating domain '{domain_name}'.")

def list_firewalls(manager):
    print("\n--- Firewalls ---")
    firewalls = manager.get_all_firewalls()
    if firewalls:
        for fw in firewalls:
            print(f"ID: {fw.id}, Name: {fw.name}, Status: {fw.status}")
    else:
        print("No firewalls found.")

def create_firewall(manager, name, inbound_rules=None, outbound_rules=None, droplet_ids=None, tags=None):
    print("\n--- Creating Firewall ---")
    new_firewall = digitalocean.Firewall(token=manager.token,
                                         name=name,
                                         inbound_rules=inbound_rules or [],
                                         outbound_rules=outbound_rules or [],
                                         droplet_ids=droplet_ids or [],
                                         tags=tags or [])
    new_firewall.create()
    print(f"Creating firewall '{name}'. Check DigitalOcean console for status.")

def list_ssh_keys(manager):
    print("\n--- SSH Keys ---")
    keys = manager.get_all_sshkeys()
    if keys:
        for key in keys:
            print(f"ID: {key.id}, Name: {key.name}, Fingerprint: {key.fingerprint}")
    else:
        print("No SSH keys found.")

def create_ssh_key(manager, name, public_key):
    print("\n--- Creating SSH Key ---")
    new_key = digitalocean.SSHKey(token=manager.token, name=name, public_key=public_key)
    new_key.create()
    print(f"Creating SSH key '{name}'.")

# --- New functions for 'create-c2-redirector' ---

def _wait_for_droplet_active(droplet, timeout=360, interval=15):
    """Waits for a droplet to become active and have an IP address."""
    start_time = time.time()
    print(f"Waiting for droplet {droplet.name} (ID: {droplet.id}) to become active and get an IP...")
    while True:
        try:
            droplet.load() # Reload droplet data
        except digitalocean.DataReadError as e:
            current_time = time.time()
            if current_time - start_time > timeout:
                print(f"Timeout waiting for droplet {droplet.name} after API error: {e}")
                return False
            print(f"Error loading droplet status: {e}. Retrying in {interval}s...")
            time.sleep(interval)
            continue # Retry loading

        if droplet.status == 'active' and droplet.ip_address:
            print(f"Droplet {droplet.name} is active. IP Address: {droplet.ip_address}")
            return True
        
        current_time = time.time()
        if current_time - start_time > timeout:
            print(f"Timeout waiting for droplet {droplet.name} to become active. Last status: {droplet.status}")
            return False
        
        print(f"Droplet status: {droplet.status}. Waiting {interval}s...")
        time.sleep(interval)

def create_droplet_and_run_command(manager, name, region, size, image, ssh_key_identifiers, private_key_path, command_to_run, ssh_user, c2_ip, passp):
    """Creates a droplet, waits for it, and runs a command via SSH."""
    # Ensure paramiko is available
    try:
        import paramiko
    except ImportError:
        print("Error: 'paramiko' library is required for 'create-c2-redirector' functionality.")
        print("Please install it using: pip install paramiko")
        sys.exit(1)

    print(f"\n--- Creating Droplet '{name}' for command execution ---")
    print(f"  Region: {region}, Size: {size}, Image: {image}")
    if not ssh_key_identifiers:
        print("Error: At least one SSH key identifier (--ssh_keys) must be provided for 'create-c2-redirector'.")
        return

    resolved_ssh_keys = []
    for key_id in ssh_key_identifiers:
        try:
            key_obj = manager.get_ssh_key(key_id)
            resolved_ssh_keys.append(key_obj)
        except digitalocean.DataReadError:
            print(f"Warning: SSH Key with identifier '{key_id}' not found in DigitalOcean. It will not be added to the droplet.")
    
    if not resolved_ssh_keys:
        print("Error: None of the provided SSH key identifiers could be found in DigitalOcean. Cannot create droplet for SSH access.")
        return

    print(f"  Using SSH keys: {[key.name for key in resolved_ssh_keys]}")

    droplet_to_create = digitalocean.Droplet(token=manager.token,
                                             name=name,
                                             region=region,
                                             size_slug=size,
                                             image=image,
                                             ssh_keys=resolved_ssh_keys,
                                             backups=False) # Add other params as needed
    
    try:
        droplet_to_create.create()
        print(f"Droplet '{name}' (ID: {droplet_to_create.id}) creation initiated.")
    except digitalocean.Error as e:
        print(f"Error creating droplet: {e}")
        return

    if not _wait_for_droplet_active(droplet_to_create):
        print(f"Droplet '{name}' did not become active in time. Aborting command execution.")
        # Consider adding droplet deletion here if it's a transient/failed setup
        # droplet_to_create.destroy()
        # print(f"Droplet '{name}' (ID: {droplet_to_create.id}) has been marked for deletion due to activation failure.")
        return

    droplet_ip = droplet_to_create.ip_address
    if not droplet_ip: # Should be caught by _wait_for_droplet_active, but double check
        print(f"Error: Droplet '{name}' is active but no IP address found. Cannot SSH.")
        return

    print("Sleeping for 60s to allow droplet to fully intialize")
    time.sleep(60)

    print(f"\n--- Connecting to {droplet_ip} as '{ssh_user}' to run command ---")

    ssh_client = None
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Not recommended for production without verification
        
        # Try to connect a few times as SSH daemon might take a moment
        connect_attempts = 6
        for attempt in range(connect_attempts):
            try:
                ssh_client.connect(droplet_ip, username=ssh_user, key_filename=private_key_path, passphrase=passp, timeout=20)
                print("Redirector SSH connection successful.")
                break
            except Exception as e_connect:
                if attempt < connect_attempts - 1:
                    print(f"SSH connection attempt {attempt+1} failed: {e_connect}. Retrying in 10s...")
                    time.sleep(10)
                else:
                    raise e_connect # Raise the last error if all attempts fail
        else: # This else belongs to the for loop, executed if loop completes without break
            print("Failed to connect via SSH after several attempts.")
            return

        command_to_run = command_to_run.replace("REDIRECTOR_IP_ADDRESS", droplet_ip)
        command_to_run = command_to_run.replace("C2_IP_ADDRESS", c2_ip)

        stdin, stdout, stderr = ssh_client.exec_command(command_to_run)
        
        print("\n--- Command Output ---")
        cmd_output = stdout.read().decode()
        cmd_error = stderr.read().decode()

        if cmd_output:
            print("Stdout:")
            print(cmd_output)
        if cmd_error:
            print("Stderr:")
            print(cmd_error)
        
        exit_status = stdout.channel.recv_exit_status()
        print(f"Command exit status: {exit_status}")

    except paramiko.AuthenticationException:
        print("Authentication failed. Please check your private key, its permissions, and the SSH user.")
    except paramiko.SSHException as ssh_ex:
        print(f"SSH connection error: {ssh_ex}")
    except FileNotFoundError:
        print(f"Error: Private SSH key file not found at '{private_key_path}'.")
    except Exception as e:
        print(f"An unexpected error occurred during SSH or command execution: {e}")
    finally:
        if ssh_client:
            ssh_client.close()
            print("Redirector SSH connection closed. (Ignore most of the warnings it probably worked)")
            print(f"Successfully created a redirector server with ip {droplet_ip}")

# --- Main function ---
def main():
    parser = argparse.ArgumentParser(description="Interact with DigitalOcean.")
    parser.add_argument("api_key", help="Your DigitalOcean API key")
    parser.add_argument("resource", help="Resource to manage (droplets, domains, firewalls, keys)")
    parser.add_argument("action", help="Action to perform (list, create, create-c2-redirector for droplets)")
    
    # Arguments for create_droplet and create_droplet_and_run_command
    parser.add_argument("--name", help="Name of the resource (e.g., droplet name, domain name)")
    parser.add_argument("--region", help="Droplet region (e.g., nyc3, sfo3)")
    parser.add_argument("--size", help="Droplet size slug (e.g., s-1vcpu-1gb)")
    parser.add_argument("--image", help="Droplet image slug (e.g., ubuntu-22-04-x64)")
    parser.add_argument("--ssh_keys", nargs='+', help="List of SSH key IDs or fingerprints for droplet creation. Required for 'create-c2-redirector'.")
    
    # Arguments for create_ssh_key
    parser.add_argument("--public_key_file", help="Path to the public SSH key file for key creation")
    
    # Arguments for create_firewall
    parser.add_argument("--inbound_rules", type=json.loads, help='JSON string for inbound firewall rules')
    parser.add_argument("--outbound_rules", type=json.loads, help='JSON string for outbound firewall rules')
    parser.add_argument("--droplet_ids", nargs='+', type=int, help='List of droplet IDs for firewall')
    parser.add_argument("--tags", nargs='+', help='List of tags for firewall')

    # New arguments for 'create-c2-redirector'
    parser.add_argument("--private-key-path", help="Path to your private SSH key file for 'create-c2-redirector'")
    parser.add_argument("--private-key-passphrase", help="The passphrase for the private SSH key. Leave blank if none. Needed for'create-c2-redirector'")
    parser.add_argument("--C2-IP", help="The C2 Server IP that will be redirected to for 'create-c2-redirector'")
    parser.add_argument("--ssh-user", help=f"User for SSH connection for 'create-c2-redirector' (default: {DEFAULT_SSH_USER})")


    args = parser.parse_args()

    try:
        manager = digitalocean.Manager(token=args.api_key)
    except digitalocean.TokenError as e:
        print(f"Error: Invalid DigitalOcean API key or connection issue: {e}")
        sys.exit(1)


    if args.resource == "droplets":
        if args.action == "list":
            list_droplets(manager)
        elif args.action == "create":
            if not all([args.name, args.region, args.size, args.image]):
                print("Error: --name, --region, --size, and --image are required for droplet creation.")
                return
            # The create_droplet function now returns the droplet object, but for this action, we don't need to use it.
            create_droplet(manager, args.name, args.region, args.size, args.image, args.ssh_keys)
        elif args.action == "create-c2-redirector":
            # Check for paramiko import again, specifically for this action
            try:
                import paramiko 
            except ImportError:
                print("Error: 'paramiko' library is required for 'create-c2-redirector'.")
                print("Please install it using: pip install paramiko")
                sys.exit(1)

            if not args.ssh_keys:
                print("Error: --ssh_keys (one or more SSH key IDs/fingerprints) is required for 'create-c2-redirector'.")
                return
            if not args.private_key_path:
                print("Error: --private-key-path is required for 'create-c2-redirector'.")
                return
            if not args.private_key_passphrase:
                print("Error: --private-key-passphrase is required for 'create-c2-redirector'.")
                return
            if not args.C2_IP:
                print("Error: --C2-IP is required for 'create-c2-redirector'.")
                return

            droplet_name = args.name if args.name else DEFAULT_DROPLET_NAME
            droplet_region = args.region if args.region else DEFAULT_DROPLET_REGION
            droplet_size = args.size if args.size else DEFAULT_DROPLET_SIZE
            droplet_image = args.image if args.image else DEFAULT_DROPLET_IMAGE
            ssh_user = args.ssh_user if args.ssh_user else DEFAULT_SSH_USER
            
            create_droplet_and_run_command(manager,
                                           droplet_name,
                                           droplet_region,
                                           droplet_size,
                                           droplet_image,
                                           args.ssh_keys, # This is a list of key IDs/fingerprints
                                           args.private_key_path,
                                           REDIRECTOR_SETUP_SCRIPT,
                                           ssh_user, args.C2_IP, args.private_key_passphrase)
        else:
            print(f"Unknown action '{args.action}' for droplets. Choose from 'list', 'create', 'create-c2-redirector'.")
    elif args.resource == "domains":
        if args.action == "list":
            list_domains(manager)
        elif args.action == "create":
            if not args.name:
                print("Error: Name is required for domain creation.")
                return
            create_domain(manager, args.name)
        else:
            print(f"Unknown action '{args.action}' for domains.")
    elif args.resource == "firewalls":
        if args.action == "list":
            list_firewalls(manager)
        elif args.action == "create":
            if not args.name:
                print("Error: Name is required for firewall creation.")
                return
            create_firewall(manager, args.name, args.inbound_rules, args.outbound_rules, args.droplet_ids, args.tags)
        else:
            print(f"Unknown action '{args.action}' for firewalls.")
    elif args.resource == "keys":
        if args.action == "list":
            list_ssh_keys(manager)
        elif args.action == "create":
            if not all([args.name, args.public_key_file]):
                print("Error: Name and --public_key_file are required for SSH key creation.")
                return
            try:
                with open(args.public_key_file, 'r') as f:
                    public_key_content = f.read().strip()
                create_ssh_key(manager, args.name, public_key_content)
            except FileNotFoundError:
                print(f"Error: Public key file '{args.public_key_file}' not found.")
        else:
            print(f"Unknown action '{args.action}' for SSH keys.")
    else:
        print(f"Unknown resource '{args.resource}'. Choose from droplets, domains, firewalls, keys.")

if __name__ == "__main__":
    main()
