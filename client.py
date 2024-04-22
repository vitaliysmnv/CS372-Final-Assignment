# Requires the following packages:
# pip install requests
# pip install ntplib
# pip install dnspython

import os
import datetime
import socket
import struct
import threading
import time
import zlib
import random
import string
import requests
import ntplib
import dns.resolver
import dns.exception
import socket
import json
import threading
import time
from socket import gaierror
from time import ctime
from typing import Union, Any, Tuple, Optional, List, Dict
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import PromptSession
import signal

shutdown_flag: bool = False
saved_messages = []
# Define variables
service_pre_prompt = '''
#############################  SERVICES MONITORED #############################'''
service_post_prompt = '''
###############################################################################
'''
service_types = ["HTTP", "HTTPS", "ICMP", "DNS", "NTP", "TCP", "UDP", "TCP Local Server"]
num_service_types = len(service_types)

welcome_prompt = '''
###############################################################################
###############################################################################
##                                                                           ##
##           Hello! Welcome to the Network Monitoring Application!           ##
##                              Vitaliy Samonov                              ##
##                                                                           ##
###############################################################################
###############################################################################
'''
services = []
service_threads = []
icmp_tools = ['ping', 'traceroute']


def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum.
    """

    s: int = 0  # Initialize the sum to 0.

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes (8-bits each) into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes.
        w: int = (data[i] << 8) + (data[i + 1])
        s += w  # Add the 16-bit word to the sum.

    # Add the overflow back into the sum.
    # If the sum is larger than 16 bits, the overflow will be in the higher bits.
    # (s >> 16) extracts the overflow by shifting right by 16 bits.
    # (s & 0xffff) keeps only the lower 16 bits of the sum.
    # The two parts are then added together.
    s = (s >> 16) + (s & 0xffff)

    # Complement the result.
    # ~s performs a bitwise complement (inverting all the bits).
    # & 0xffff ensures the result is a 16-bit value by masking the higher bits.
    s = ~s & 0xffff

    return s  # Return the calculated checksum.


def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payload in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet by combining the specified ICMP type, code, and sequence number
    with a data payload of a specified size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means:
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack(
        'bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It's a sequence of a single randomly chosen alphanumeric character (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code,
                         socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data


def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Union[Tuple[Any, float], Tuple[Any, None]]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceeded before receiving a reply, the function returns None for the ping time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in milliseconds.
    If the request times out, the function returns None for the ping time. The address part of the tuple is also None if no reply is received.
    """

    # Create a raw socket with the Internet Protocol (IPv4) and ICMP.
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_RAW allows sending raw packets (including ICMP).
    # socket.IPPROTO_ICMP specifies the ICMP protocol.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        # Create an ICMP Echo Request packet.
        # icmp_type=8 and icmp_code=0 are standard for Echo Request.
        # sequence_number is used to match Echo Requests with Replies.
        packet: bytes = create_icmp_packet(
            icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        # The second argument of sendto is a tuple (host, port).
        # For raw sockets, the port number is irrelevant, hence set to 1.
        sock.sendto(packet, (host, 1))

        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000

            # Return the address of the replier and the total ping time.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None


def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """
    # Header row for the results. Each column is formatted for alignment and width.
    results = [
        f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            # The sequence number is incremented with TTL for each ping.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times.
            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL to the results list.
            results.append(
                f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms {max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(
                f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    # Join all results into a single string with newline separators and return.
    return '\n'.join(results)


def check_server_http(url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful status codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code

    except requests.RequestException:
        # This block catches any exception that might occur during the request.
        # This includes network problems, invalid URL, etc.
        # If an exception occurs, we assume the server is down.
        # Returning False for the status, and None for the status code,
        # as we couldn't successfully connect to the server to get a status code.
        return False, None


def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # The timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(
            url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A catch-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"


def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None


def check_dns_server_status(server, query, record_type) -> Tuple[bool, Optional[str]]:
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)


def check_tcp_port(ip_address: str, port: int) -> Tuple[bool, Optional[str]]:
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"


def check_udp_port(ip_address: str, port: int, timeout: int = 3) -> Tuple[bool, Optional[str]]:
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"


# Function to check HTTP service
def check_http_service(http_url: str, sock: socket.socket) -> bool:
    http_server_status, http_server_response_code = check_server_http(http_url)
    timestamped_print(sock,
        f"HTTP URL: {http_url}, HTTP server status: {http_server_status}, Status Code: {http_server_response_code if http_server_response_code is not None else 'N/A'}")

# Function to check HTTPS service


def check_https_service(https_url: str, timeout: int, sock: socket.socket) -> bool:
    https_server_status, https_server_response_code, description = check_server_https(
        https_url, timeout)
    timestamped_print(sock,
        f"HTTPS URL: {https_url}, HTTPS server status: {https_server_status}, Status Code: {https_server_response_code if https_server_response_code is not None else 'N/A'}, Description: {description}")

# Function to check ICMP (Ping)


def check_ping_service(host: str, sock: socket.socket) -> bool:
    ping_addr, ping_time = ping(host)
    timestamped_print(sock, f"ICMP(ping): Server: {host} - {ping_time:.2f} ms" if (
        ping_addr and ping_time is not None) else "{host} (ping): Request timed out or no reply received")


def check_traceroute_service(host: str, sock: socket.socket) -> bool:
    message = f"ICMP(traceroute): Server: {host} - "
    sock.send(message.encode('utf-8'))
    print(f"ICMP(traceroute): Server: {host} - ", end="")
    timestamped_print(sock, traceroute(host))

# Function to check DNS service


def check_dns_service(dns_server: str, dns_query: str, dns_record_type: str, sock: socket.socket) -> bool:
    # while True:
    dns_server_status, dns_query_results = check_dns_server_status(
        dns_server, dns_query, dns_record_type)
    timestamped_print(sock,
        f"DNS Server: {dns_server}, Status: {dns_server_status}, {dns_record_type} Records Results: {dns_query_results}")

# Function to check NTP service


def check_ntp_service(ntp_server: str, sock: socket.socket) -> bool:
    ntp_server_status, ntp_server_time = check_ntp_server(ntp_server)
    timestamped_print(sock,
        f"NTP: {ntp_server} is up. Time: {ntp_server_time}" if ntp_server_status else f"NTP: {ntp_server} is down.")

# Function to check TCP port


def check_tcp_service(tcp_port_server: str, tcp_port_number: int, sock: socket.socket) -> bool:
    tcp_port_status, tcp_port_description = check_tcp_port(
        tcp_port_server, tcp_port_number)
    timestamped_print(sock,
        f"TCP: Server: {tcp_port_server}, TCP Port: {tcp_port_number}, TCP Port Status: {tcp_port_status}, Description: {tcp_port_description}")

# Function to check UDP port


def check_udp_service(udp_port_server: str, udp_port_number: int, sock: socket.socket) -> bool:
    udp_port_status, udp_port_description = check_udp_port(
        udp_port_server, udp_port_number)
    timestamped_print(sock, 
        f"UDP: Server: {udp_port_server}, UDP Port: {udp_port_number}, UDP Port Status: {udp_port_status}, Description: {udp_port_description}")


def print_service_list(services: List[dict]) -> Tuple[bool, Optional[str]]:
    """
    Function to print the list of services.
    :param services: List of dictionaries containing service details.
    :return: Tuple containing a boolean indicating success and an optional error message.
    """
    if len(services) > 0:
        print(service_pre_prompt)
        # Print the list of services
        for index, item in enumerate(services, start=1):
            print(f"Service {index}:", end="")
            for key, value in item.items():
                formatted_key = key.replace('_', ' ').capitalize()
                print(f"\t{formatted_key}: {value}", end="")
            print()
        print(service_post_prompt)
    else:
        print(service_pre_prompt + service_post_prompt)


def check_tcp_local_service(tcp_port_number: int, sock: socket.socket) -> bool:
    tcp_port_status, tcp_port_description = check_tcp_port(
        '127.0.0.1', tcp_port_number)
    timestamped_print(
        sock, f"TCP Local Server: 127.0.0.1, Port: {tcp_port_number}, Port Status: {tcp_port_status}, Description: {tcp_port_description}")



def input_configurations() -> list:
    """
    Function to input monitoring configurations from the user.
    Returns a list of dictionaries,
    each containing configuration details for a service.
    """
    configurations = []
    while True:
        print_service_list(configurations)
        for index, item in enumerate(service_types, start=1):
            print(f"Service {index} - {item}")
        print()
        print(
            f"Select which service you would like to monitor (1-{num_service_types}):")

        while True:
            try:
                user_input = int(input())
                if 1 <= user_input <= num_service_types:
                    break
                else:
                    print(
                        f"Please enter an number within the range 1-{num_service_types}")
            except ValueError:
                print("Invaild input. Please enter a valid number")
        service_type = service_types[user_input - 1]
        configuration = {}
        configuration["service_type"] = service_type
        if service_type in ['HTTP', 'HTTPS']:
            address = input("Enter URL to monitor: ").strip()
            configuration['address'] = address
            if service_type == 'HTTPS':
                timeout = int(
                    input("Enter timeout in seconds (default is 5): ").strip() or 5)
                configuration['timeout'] = timeout
        elif service_type == 'ICMP':
            address = input("Enter server address: ").strip()
            print("1. Ping")
            print("2. Traceroute")
            while True:
                try:
                    tool = int(input("Select the tool you want to use: "))
                    if 1 <= tool <= 2:
                        break
                    else:
                        print("Please enter an number within the range 1-2")
                except ValueError:
                    print("Invaild input. Please enter a valid number")
            configuration['tool'] = icmp_tools[tool - 1]
            configuration['address'] = address
        elif service_type == 'NTP':
            address = input("Enter NTP server address: ").strip()
            configuration['address'] = address
        elif service_type == 'DNS':
            address = input("Enter DNS server address: ").strip()
            query = input("Enter DNS query: ").strip()
            while True:
                record_type = input("Enter record type (A, AAAA, MX, CNAME.): ").strip()
                if record_type.upper() in ["A","AAAA","MX","CNAME"]:
                    break
                print ("Try again")
            configuration['address'] = address
            configuration['query'] = query
            configuration['record_type'] = record_type
        elif service_type in ['TCP', 'UDP']:
            address = input("Enter server address to check: ").strip()
            port = int(input("Enter port number: ").strip())
            configuration['address'] = address
            configuration['port'] = port
        elif service_type == 'TCP Local Server':
            port = int(input("Enter port number: ").strip())
            configuration['port'] = port
        else:
            print("Invalid service type.")
            return None
        frequency = int(input("Frequency to check server(in seconds): ").strip())
        configuration['frequency'] = frequency
        configurations.append(configuration)
        while True:
            try:
                user_input = input("Add another service? (y/n)")
                if user_input.lower() == 'n' or user_input.lower() == 'y':
                    break
                else:
                    print("Please enter y or n")
            except ValueError:
                print("Please enter y or n")
        if user_input.lower() == 'n':
            break
    return configurations


# Custom print function with timestamp
def timestamped_print(sock, *args, **kwargs):
    """
    Custom print function that adds a timestamp
    to the beginning of the message.
    Args:
        *args: Variable length argument list.
        **kwargs: Arbitrary keyword arguments.
        These are passed to the built-in print function.
    """
    # Get the current time and format it
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    messages_to_send = "[{}]: {}".format(timestamp, " ".join(map(str, args)), **kwargs)
    message = create_message( "log", data=messages_to_send)
    sock.send(message.encode('utf-8'))
    
    """
    global saved_messages
    
    try:
        if len(saved_messages)>0:
            for saved_message in saved_messages:
                 sock.send(saved_message.encode('utf-8'))
            saved_messages.clear()
        sock.send(message.encode('utf-8'))
    except Exception as e:
        saved_messages.append(message)
    """ 
    print(f"[{timestamp}]: ", *args, **kwargs)


def service_check_worker(stop_event: threading.Event, service_item: Dict[str, Any]):
    """
    Worker function to perform service checks.
    """
    service = service_item['service_type']
    frequency = service_item['frequency']

    while not stop_event.is_set():
        # Perform service check based on service type
        if service == 'HTTP':
            check_http_service(service_item['address'])
        elif service == 'HTTPS':
            check_https_service(
                service_item['address'], service_item['timeout'])
        elif service == 'ICMP':
            if service_item['tool'] == 1:
                check_traceroute_service(service_item['address'])
            else:
                check_ping_service(service_item['address'])
        elif service == 'DNS':
            check_dns_service(
                service_item['address'], service_item['query'], service_item['record_type'])
        elif service == 'NTP':
            check_ntp_service(service_item['address'])
        elif service == 'TCP':
            check_tcp_service(service_item['address'], service_item['port'])
        elif service == 'UDP':
            check_udp_service(service_item['address'], service_item['port'])
        elif service == 'TCP Local Server':
            check_tcp_local_service(service_item['port'])
        # Sleep for the specified frequency
        time.sleep(frequency)


# Function to handle service check
def handle_service(service_info: dict, sock: socket.socket):
    global shutdown_flag
    while not shutdown_flag:
        service_type = service_info['service_type']
        if service_type == 'HTTP':
            check_http_service(service_info['address'], sock)
        elif service_type == 'HTTPS':
            check_https_service(service_info['address'], 5, sock)
        elif service_type == 'ICMP':
            if service_info['tool'] == 1:
                check_traceroute_service(service_info['address'], sock)
            else:
                check_ping_service(service_info['address'], sock)
        elif service_type == 'DNS':
            check_dns_service(service_info['address'], service_info['query'], service_info['record_type'], sock)
        elif service_type == 'NTP':
            check_ntp_service(service_info['address'], sock)
        elif service_type in ['TCP', 'TCP Local Server']:
            check_tcp_service(service_info['address'], service_info['port'], sock)
        elif service_type == 'UDP':
            check_udp_service(service_info['address'], service_info['port'], sock)
        time.sleep(service_info['interval'])


def signal_handler(signum: int, frame: Any) -> None:
    global shutdown_flag
    shutdown_flag = True
    print("\nShutdown signal received. Initiating graceful shutdown...")

def create_message(action: str, data: Any = None, count: int = 0) -> str: 
    message: Dict[str, Any] = {"type": action, "data": data} 
    return json.dumps (message)

def parse_message(message: str) -> Dict[str, Any]:
    return json.loads(message)

def handle_server_messages(sock: socket.socket) -> None:
    global shutdown_flag
    try:
        while not shutdown_flag:
            try:
                message_bytes: bytes = sock.recv(1024)
                if not message_bytes:
                    print("\n[Client] Server connection closed.") 
                    # break # Server closed connection or shutdown 
                message: str = message_bytes.decode('utf-8') 
                parsed_message: Dict[str, Any] = parse_message(message) 
                print(f"\n[Client] Message from server: {parsed_message}")
                
                if parsed_message["type"] == "configuration":
                    """
                    for thread in service_threads:
                        if thread.is_alive():
                            thread.join()  # Wait for the thread to finish before removing it
                        service_threads.remove(thread)
                    """
                    data = parsed_message.get("data", [])
                    for service_info in data:
                        service_thread = threading.Thread(target=handle_service, args=(service_info, sock))
                        service_thread.start()
                        service_threads.append(service_thread)
                    print(f" [Client] Received configuration from server: {data}")
            except socket.error:
                print("\n[Client] Lost connection to server. Attempting to reconnect...")
                break

    finally:
        if not shutdown_flag:
            reconnect()
            
def reconnect():
    global shutdown_flag
    while not shutdown_flag:
        try:
            print("[Client] Attempting to reconnect to the server...")
            start_client()
            break
        except socket.error:
            print("[Client] Reconnection failed. Trying again in 5 seconds...") 
            time.sleep(5)

def start_client():
    global shutdown_flag
    host: str = 'localhost'
    port: int = 54321
    while not shutdown_flag:
        client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        try:
            client_socket.connect((host, port))
            print("[Client] Connected to server.")
            server_message_thread = threading. Thread(target=handle_server_messages, args=(client_socket,), daemon=True) 
            server_message_thread.start()
            server_message_thread.join()
        except socket.error as e:
            print(f" [Client] Socket connection error: {e}. Attempting to reconnect...")
            reconnect()
        finally:
            if shutdown_flag:
                client_socket.close()
                print("\n[Client] Client shutdown gracefully.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler) 
    signal.signal(signal.SIGTERM, signal_handler)
    start_client()