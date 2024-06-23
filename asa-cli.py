import os
import paramiko
import logging
from dotenv import load_dotenv
import argparse

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(filename='asa_nat_update.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_env_variable(var_name):
    """
    Get the value of an environment variable.

    Args:
        var_name (str): The name of the environment variable.

    Returns:
        str: The value of the environment variable.

    Raises:
        ValueError: If the environment variable is not set.

    """
    value = os.getenv(var_name)
    if value is None:
        raise ValueError("Environment variable '{}' is not set.".format(var_name))
    return value

def get_domain(domain=None, args=None):
    """
    Retrieves the domain value from the environment variable, CLI argument, or .env file.

    Args:
        domain (str, optional): The domain value to use. If not provided, it will be retrieved from the environment variable, CLI argument, or .env file.
        args (argparse.Namespace, optional): The command-line arguments. Defaults to None.

    Returns:
        str: The domain value.

    Raises:
        ValueError: If the domain is not defined in the .env file or provided via the --domain argument.
    """
    # Check if domain key exists in .env
    env_domain = os.getenv("DOMAIN")
    # Use CLI argument if provided, otherwise use .env value
    if args is not None:
        domain = args.domain
    else:
        domain = None
    domain = domain or env_domain
    if not domain:
        raise ValueError("Domain must be provided either through args or as an environment variable")
    return domain

def format_domain(domain):
    """
    Formats the domain name by converting it to uppercase and replacing dots with hyphens.

    Args:
        domain (str): The domain name to format ie:.. example.com.

    Returns:
        str: The formatted domain name ie:.. EXAMPLE-COM.
    """
    return domain.upper().replace('.', '-')
     
def execute_ssh_command(host, port, username, password, command):
    """
    Executes a command on a remote device via SSH.

    Args:
        host (str): The hostname or IP address of the remote device.
        port (int): The port number to connect to on the remote device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        command (str): The command to execute on the remote device.

    Returns:
        str: The output from the command.

    """
    # Create a new SSH client
    ssh_client = paramiko.SSHClient()
    
    # Automatically add the remote device's SSH key to the list of known hosts
    # (Not recommended for production use! Better to manually manage host keys.)
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the remote device
        ssh_client.connect(host, port=port, username=username, password=password)
        
        # Execute the command
        # Remove unused variables
        _, stdout, stderr = ssh_client.exec_command(command)
        
        # Read the command output
        output = stdout.read()
        
        # Optionally, you can also capture and handle errors
        error = stderr.read()
        if error:
            print("Error executing command: {} - {}".format(error, command))
        
        return output
    except Exception as e:
        print("Failed to execute command via SSH: {} - {}".format(e, command)) 
        
    finally:
        # Ensure the connection is closed
        ssh_client.close()
        
def get_assigned_ip_and_mac(hostname, port, username, password, domain):
    """
    Retrieves the assigned IP address, MAC address, and public IP for a given domain.

    Args:
        hostname (str): The hostname or IP address of the device to connect to.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name to search for in the ARP and NAT tables.

    Returns:
        tuple: A tuple containing the assigned Public IP, Private IP, and MAC address.
               If an error occurs, None is returned for all values.
    """
    try:
        domain_formatted = format_domain(domain)
        command = 'show arp | include {}'.format(domain_formatted)
        output = execute_ssh_command(hostname, port, username, password, command)
        if output:
            arp_entry = output.split()
            private_ip = arp_entry[1]
            mac_address = arp_entry[3] if len(arp_entry) > 3 else None
        else:
            logging.error('Error executing command "{}"'.format(command))
            return None, None, None

        command = 'show run nat | include {}'.format(domain_formatted)
        nat_output = execute_ssh_command(hostname, port, username, password, command)
        if nat_output:
            public_ip = None
            nat_lines = nat_output.split('\n')
            for line in nat_lines:
                if 'object network WEB-SERVER-{}'.format(domain_formatted) in line:
                    parts = line.split()
                    if 'nat' in parts:
                        public_ip = parts[-1]
        else:
            logging.error('Error executing command "{}"'.format(command))
            return None, None, None

        return private_ip, mac_address, public_ip

    except Exception as e:
        logging.error('Unexpected error: {}'.format(e))
        return None, None, None

def show_interface_stats(hostname, port, username, password, domain):
    """
    Retrieves interface statistics for a given domain on a specified host.

    Args:
        hostname (str): The hostname or IP address of the device.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain for which to retrieve interface statistics.

    Returns:
        str: The output of the 'show conn address' command.

    """
    domain_formatted = format_domain(domain)
    command = 'show conn address {}'.format(domain_formatted)
    return execute_ssh_command(hostname, port, username, password, command)

def show_environment_in_use(hostname, port, username, password, domain):
    """
    Retrieves the environment in use for a given hostname, username, password, and domain.

    Args:
        hostname (str): The hostname of the device.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name.

    Returns:
        str: The environment in use. Possible values are "blue", "green", or "Unknown".
    """
    domain_formatted = format_domain(domain)
    command = 'show run object network WEB-SERVER-{}'.format(domain_formatted)
    output = execute_ssh_command(hostname, port, username, password, command)
    if output:
        return "blue" if "BLUE" in output else "green" if "GREEN" in output else "Unknown"
    else:
        return "Unknown"

def show_connection_count(hostname, port, username, password, domain):
    """
    Retrieves the connection count for a specific web server domain on a given hostname.

    Args:
        hostname (str): The hostname or IP address of the device to connect to.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The web server domain to retrieve the connection count for.

    Returns:
        str or None: The output of the command if successful, None otherwise.
    """
    domain_formatted = format_domain(domain)
    command = 'show conn count address WEB-SERVER-{}'.format(domain_formatted)
    output = execute_ssh_command(hostname, port, username, password, command)
    if output:
        return output
    else:
        return None

def show_traffic(hostname, port, username, password, domain):
    """
    Retrieves traffic information for a specific domain from a network device.

    Args:
        hostname (str): The hostname or IP address of the network device.
        port (int): The port number to connect to on the network device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name to filter the traffic information.

    Returns:
        str: The output of the 'show traffic' command filtered by the specified domain.

    """
    domain_formatted = format_domain(domain)
    command = 'show traffic | include WEB-SERVER-{}'.format(domain_formatted)
    return execute_ssh_command(hostname, port, username, password, command)

def show_threat_detection(hostname, port, username, password, domain):
    """
    Retrieves threat detection statistics for a specific web server domain.

    Args:
        hostname (str): The hostname or IP address of the device.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name of the web server.

    Returns:
        str: The output of the command executed on the device.

    """
    domain_formatted = format_domain(domain)
    command = 'show threat-detection statistics top WEB-SERVER-{}'.format(domain_formatted)
    if command:
        return execute_ssh_command(hostname, port, username, password, command)
    else:
        return None

def show_current_config(hostname, port, username, password, domain):
    """
    Retrieves the current configuration for a given hostname, username, password, and domain.

    Args:
        hostname (str): The hostname or IP address of the device.
        port (int): The port number to connect to on the device.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name.

    Returns:
        str: The current configuration output.

    """
    domain_formatted = format_domain(domain)
    commands = [
        'show run object network WEB-SERVER-{}'.format(domain_formatted),
        'show run nat | include {}'.format(domain_formatted),
        'show access-list | include {}'.format(domain_formatted)
    ]
    config_output = ""
    for command in commands:
        output = execute_ssh_command(hostname, port, username, password, command)  # Pass the correct arguments to execute_ssh_command
        if output:
            config_output += output + "\n"
    return config_output

def update_nat_configuration(hostname, port, username, password, domain, switch_to):
    """
    Update NAT configuration for a given domain on a network switch.

    Args:
        hostname (str): The hostname or IP address of the network switch.
        port (int): The port number for SSH connection.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name for the NAT configuration.
        switch_to (str): The switch to which the NAT configuration should be switched.
                         Must be either 'blue' or 'green'.

    Raises:
        ValueError: If the value of `switch_to` is not 'blue' or 'green'.

    Returns:
        None
    """
    try:
        if switch_to.lower() not in ['blue', 'green']:
            raise ValueError("Invalid value for SWITCH_TO. Must be 'blue' or 'green'.")
        
        domain_formatted = format_domain(domain)
        target_object = '{}-{}'.format(domain_formatted, switch_to.upper())

        command_list = [
            'enable',
            'config terminal',
            'object network WEB-SERVER-{}'.format(domain_formatted.upper()),
            'nat (inside,outside) static {}'.format(target_object),
            'write memory'
        ]

        for command in command_list:
            output = execute_ssh_command(hostname, port, username, password, command)
            if output is None:
                logging.error('Error executing command "{}"'.format(command))
            else:
                logging.info('Executed command: {}'.format(command))
        
        logging.info('NAT configuration updated successfully for {}.'.format(domain))

    except Exception as e:
        logging.error('Unexpected error: {}'.format(e))

def add_new_domain(hostname, port, username, password, domain, public_ip, private_ip):
    """
    Adds a new domain to the ASA by creating the appropriate network objects and NAT rules.

    Args:
        hostname (str): The hostname or IP address of the ASA device.
        port (int): The port number for SSH connection.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain name to add.
        private_ip (str): The private IP address of the domain.
        public_ip (str): The public IP address of the domain.

    Raises:
        ValueError: If any of the required arguments are missing.

    Returns:
        None
    """
    try:
        if not all([hostname, port, username, password, domain, public_ip, private_ip]):
            raise ValueError("All arguments are required.")

        domain_formatted = format_domain(domain)

        command_list = [
            'enable',
            'config terminal',
            f'object network WEB-SERVER-{domain_formatted}',
            f'host {private_ip}',
            f'nat (inside,outside) static {public_ip}',
            'write memory'
        ]

        for command in command_list:
            output = execute_ssh_command(hostname, port, username, password, command)
            if output is None:
                logging.error('Error executing command "{}"'.format(command))
            else:
                logging.info('Executed command: {}'.format(command))

        logging.info('New domain {} added successfully.'.format(domain))

    except Exception as e:
        logging.error('Unexpected error: {}'.format(e))

# Example usage:
# add_new_domain(hostname, port, username, password, 'newdomain.com', '203.0.113.10', '192.168.1.10')


if __name__ == "__main__":
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='Manage blue-green deployment strategy for a specific domain on Cisco ASA.')

        parser.add_argument('switch', help='Switch environment')
        parser.add_argument('ip_mac', help='show IP and MAC, stats')
        parser.add_argument('stats', help='Show interface stats')
        parser.add_argument('environment', help='Show current environment')
        parser.add_argument('conn_count', help='Show connection count')
        parser.add_argument('traffic', help='Show traffic stats')                    
        parser.add_argument('threat_detection', help='Show threat detection stats')
        parser.add_argument('show_config', help='Show current configuration')
        
        parser.add_argument('--domain', type=str, help='Domain name (e.g., example.com)')
        parser.add_argument('--switch_to', type=str, choices=['blue', 'green'], help='Environment to switch to (blue or green)')
        parser.add_argument('--interface', type=str, help='Interface name for stats (e.g., inside, outside)')

        args = parser.parse_args()

        # Pull variables from environment
        asa_host         = get_env_variable('HOSTNAME')
        asa_ssh_port     = get_env_variable('PORT')
        asa_username     = get_env_variable('USERNAME')
        asa_password     = get_env_variable('PASSWORD')
        domain_to_manage = get_domain(args.domain, args)
        
        
        if args.action == 'switch':
            if domain_to_manage and args.switch_to:
                update_nat_configuration(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage, args.switch_to)
            else:
                raise ValueError("Domain and switch_to arguments are required for 'switch' action.")
        
        elif args.action == 'ip_mac':
            if domain_to_manage:
                private_ip, mac_address, public_ip = get_assigned_ip_and_mac(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if private_ip and mac_address and public_ip:
                    print("Domain: {}\nPublic IP: {} \nPrivate IP: {}\nMAC Address: {}".format(domain_to_manage, public_ip, private_ip, mac_address))
                else:
                    print("Could not retrieve IP and MAC address for {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'ip_mac' action.")

        elif args.action == 'stats':
            if domain_to_manage:
                stats_output = show_interface_stats(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if stats_output:
                    print("Interface statistics for {}:\n{}".format(domain_to_manage, stats_output))
                else:
                    print("Could not retrieve statistics for domain {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'stats' action.")

        elif args.action == 'environment':
            if domain_to_manage:
                environment = show_environment_in_use(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                print("Environment in use for {}: {}".format(domain_to_manage, environment))
            else:
                raise ValueError("Domain argument is required for 'environment' action.")
        
        elif args.action == 'conn_count':
            if domain_to_manage:
                conn_count_output = show_connection_count(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if conn_count_output:
                    print("Connection count for {}:\n{}".format(domain_to_manage, conn_count_output))
                else:
                    print("Could not retrieve connection count for domain {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'conn_count' action.")

        elif args.action == 'traffic':
            if domain_to_manage:
                traffic_output = show_traffic(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if traffic_output:
                    print("Traffic statistics for {}:\n{}".format(domain_to_manage, traffic_output))
                else:
                    print("Could not retrieve traffic statistics for domain {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'traffic' action.")

        elif args.action == 'threat_detection':
            if domain_to_manage:
                threat_detection_output = show_threat_detection(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if threat_detection_output:
                    print("Threat detection statistics for {}:\n{}".format(domain_to_manage, threat_detection_output))
                else:
                    print("Could not retrieve threat detection statistics for domain {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'threat_detection' action.")

        elif args.action == 'show_config':
            if domain_to_manage:
                config_output = show_current_config(asa_host, asa_ssh_port, asa_username, asa_password, domain_to_manage)
                if config_output:
                    print("Current configuration for {}:\n{}".format(domain_to_manage, config_output))
                else:
                    print("Could not retrieve current configuration for domain {}".format(domain_to_manage))
            else:
                raise ValueError("Domain argument is required for 'show_config' action.")

    except ValueError as ve:
        logging.error('Configuration error: {}'.format(ve))
    except Exception as e:
        logging.error('Unexpected error during initialization: {}'.format(e))
