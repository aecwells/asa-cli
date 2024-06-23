# Cisco ASA Blue-Green Deployment Script

This script is designed to manage a blue-green deployment strategy for a specific domain on a Cisco ASA device. It provides functionality to switch between blue and green environments, retrieve IP and MAC addresses, show interface stats, environment in use, connection count, traffic stats, threat detection stats, and the current configuration.

## Table of Contents
- [ASA Configuration](#asa-configuration)
  - [Enable SSH](#enableing-ssh-on-a-cisco-asa)
    - [Enabling SSH via CLI](enabling-ssh-via-cli)
    - [Enabling SSH via GUI](enabling-ssh-via-gui)
  - [Blue/Green Network Objects](create-network-objects-for-blue-and-green-servers)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Switch Environment](#switch-environment)
  - [Show IP and MAC](#show-ip-and-mac)
  - [Show Interface Stats](#show-interface-stats)
  - [Show Environment in Use](#show-environment-in-use)
  - [Show Connection Count](#show-connection-count)
  - [Show Traffic Stats](#show-traffic-stats)
  - [Show Threat Detection Stats](#show-threat-detection-stats)
  - [Show Current Configuration](#show-current-configuration)

## ASA Configuration

### Enabling SSH on a Cisco ASA
This guide will help you enable SSH on a Cisco ASA using both the CLI (Command Line Interface) and GUI (Graphical User Interface).

#### Enabling SSH via CLI

1. **Access the ASA via Console or Telnet:**
   Connect to your ASA using a console cable or telnet.

2. **Enter Global Configuration Mode:**
   ```sh
   enable
   configure terminal
   ```
3. **Generate RSA Keys**
   ```sh
   crypto key generate rsa modulus 2048
   ``` 
4. **Enable SSH on the Desired Interface:**
   Replace `INSIDE_INTERFACE` with the interface you want to enable SSH on, and `LOCAL_IP_RANGE` with the local IP range allowed to access SSH.
   ```sh
   ssh LOCAL_IP_RANGE INSIDE_INTERFACE
   ```
5. **Configure SSH Timeout and Version:**
   ```sh
   ssh timeout 60
   ssh version 2
   ```
6. **Create a Local User for SSH Access:**
   ```sh
   username admin password YOUR_PASSWORD privilege 15
   ```
7. **Save theconfiguration**
   ```sh
   write memory
   ```
#### Example Configuration

```sh
enable
configure terminal
crypto key generate rsa modulus 2048
ssh 192.168.1.0 255.255.255.0 inside
ssh timeout 60
ssh version 2
username admin password AdminPassword privilege 15
write memory
```

#### Enabling SSH via GUI

1. **Access the ASA GUI:**
   Open a web browser and navigate to the ASA’s IP address.

2. **Log in to the ASDM:**
   Enter your username and password.

3. **Navigate to Device Management:**
   Go to `Configuration > Device Management > Management Access > ASDM/HTTPS/Telnet/SSH`.

4. **Configure SSH Settings:**
   - Click `Add` under the SSH section.
   - In the `Add SSH Access` window, configure the following:
     - **Interface:** Select the interface to enable SSH on.
     - **IP Address:** Specify the IP address range allowed to access SSH.
     - **Subnet Mask:** Enter the corresponding subnet mask.
     - **Timeout:** Set the SSH timeout period (default is 60 minutes).

5. **Generate RSA Keys:**
   - Navigate to `Configuration > Device Management > Certificate Management > Identity Certificates`.
   - Click `Add` to create a new identity certificate and follow the prompts to generate RSA keys.

6. **Create a Local User:**
   - Go to `Configuration > Device Management > Users/AAA > User Accounts`.
   - Click `Add` to create a new user with administrative privileges.

7. **Save the Configuration:**
   Click the `Save` button to apply the changes.




## Create Network Objects for Blue and Green Servers
Here’s an example of how you can manually create network objects for the blue and green servers:

```sh
# Log in to the Cisco ASA device
ssh admin@your-asa-device

# Enter configuration mode
enable
config terminal

# Create network objects for blue and green servers
# Create network objects for each domain
object network EXAMPLE-COM-BLUE
 host 192.168.1.10

object network EXAMPLE-COM-GREEN
 host 192.168.1.20

object network EXAMPLE-NET-BLUE
 host 192.168.2.10

object network EXAMPLE-NET-GREEN
 host 192.168.2.20

# Repeat for other domains...
```

2. Configure NAT Rules
Configure the NAT rules to use the `blue` network object:

```sh
# Configure NAT rules for example.com
object network WEB-SERVER-EXAMPLE-COM
 nat (inside,outside) static EXAMPLE-COM-BLUE

# Configure NAT rules for example.net
object network WEB-SERVER-EXAMPLE-NET
 nat (inside,outside) static EXAMPLE-NET-BLUE

# Repeat for other domains...
```


## Features

The script supports the following actions:

- `switch`: Switch the current environment between blue and green.
  - `--domain <domain_name>`: Specifies the domain to switch environments for.
  - `--switch_to <environment>`: Specifies the environment to switch to (`blue` or `green`).
- `ip_mac`: Display IP and MAC addresses.
- `stats`: Show interface statistics.
  - `--interface <interface_name>`: Specifies the interface to show statistics for.
- `environment`: Display the current environment.
- `conn_count`: Show the connection count.
- `traffic`: Display traffic statistics.
  - `--interface <interface_name>`: Optionally specify an interface to show traffic statistics for (`inside` or `outside`).
- `threat_detection`: Show threat detection statistics.
- `show_config`: Display the current configuration.

## Requirements

- Python 3.x
- `paramiko` library
- `python-dotenv` library

## Installation

1. Install the required Python packages:

    ```sh
    pip install -r requirements.txt
    ```

## Configuration

You can set these variables in your environment `.env` file before running the script.
The script requires the following environment variables to be set:

- `HOSTNAME`: The hostname of the Cisco ASA device.
- `PORT`: The port to connect to on the Cisco ASA device.
- `USERNAME`: The username for authentication.
- `PASSWORD`: The password for authentication.

Optional:

- `DOMAIN`: The domain to be managed. If not set, the `--domain` argument needs to be passed when running the script.

1. Create a `.env` file in the root directory of the project and add the following environment variables:

    ```env
    HOSTNAME=your_asa_hostname
    PORT=your_asa_port
    USERNAME=your_asa_username
    PASSWORD=your_asa_password
    DOMAIN=your_default_domain
    ```

2. Ensure you have logging configured. The script logs to `asa_cli_update.log` by default.

## Usage

Run the script using the command line with the appropriate action and arguments.

```sh
python asa-cli.py <action> [--domain DOMAIN] [--switch_to SWITCH_TO] [--interface INTERFACE]
```
```sh
usage: asa-cli.py [-h] [--domain DOMAIN] [--switch_to {blue,green}] [--interface INTERFACE] switch ip_mac stats environment conn_count traffic threat_detection show_config

Manage blue-green deployment strategy for a specific domain on Cisco ASA.

positional arguments:
  switch                Switch environment
  ip_mac                show IP and MAC, stats
  stats                 Show interface stats
  environment           Show current environment
  conn_count            Show connection count
  traffic               Show traffic stats
  threat_detection      Show threat detection stats
  show_config           Show current configuration

optional arguments:
  -h, --help            show this help message and exit
  --domain DOMAIN       Domain name (e.g., example.com)
  --switch_to {blue,green}
                        Environment to switch to (blue or green)
  --interface INTERFACE
                        Interface name for stats (e.g., inside, outside)
```
### Switch Environment

Switches the NAT configuration to the specified environment (blue or green).

```sh
python asa-cli.py switch --domain example.com --switch_to blue
```
```bash example
INFO - Executed command: enable
INFO - Executed command: config terminal
INFO - Executed command: object network WEB-SERVER-EXAMPLE-COM
INFO - Executed command: nat (inside,outside) static EXAMPLE-COM-BLUE
INFO - Executed command: write memory
INFO - NAT configuration updated successfully for example.com.
```

### Show IP and MAC
Displays the assigned IP and MAC addresses for the given domain.
```sh
python asa-cli.py ip_mac --domain example.com
```
```yaml
Domain: example.com
Public IP: 203.0.113.1 
Private IP: 192.168.1.1
MAC Address: 00:1A:2B:3C:4D:5E
```

### Show Interface Stats
Shows the interface statistics for the specified domain.
```sh
python asa-cli.py stats --domain example.com
```
```yaml
Interface statistics for example.com:
Interface inside: 1000 packets input, 2000 packets output
Interface outside: 500 packets input, 1000 packets output
```

### Show Environment in Use
Shows which environment (blue or green) is currently in use for the specified domain.
```sh
python asa-cli.py environment --domain example.com
```
```sh
Environment in use for example.com: blue
```

### Show Connection Count
Displays the connection count for the specified domain.

```sh
python asa-cli.py conn_count --domain example.com
```
```bash
Connection count for example.com:
100 connections
```
### Show Traffic Stats
Displays the traffic statistics for the specified domain.

```sh
python asa-cli.py traffic --domain example.com
```
```yaml
Traffic statistics for example.com:
Total traffic: 1GB
Inbound traffic: 600MB
Outbound traffic: 400MB
```

### Show Threat Detection Stats
Shows the threat detection statistics for the specified domain.

```sh
python asa-cli.py threat_detection --domain example.com
```
```yaml
Threat detection statistics for example.com:
Top threats: 5
DDoS attempts: 2
```
### Show Current Configuration
Displays the current configuration for the specified domain.

```sh
python asa-cli.py show_config --domain example.com
```
```bash
Current configuration for example.com:
object network WEB-SERVER-EXAMPLE-COM
 nat (inside,outside) static EXAMPLE-COM-BLUE
access-list outside_access_in extended permit ip any host 203.0.113.1
```
