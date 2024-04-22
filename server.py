from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout 
import socket
import threading
import signal
import json
from typing import Any, Dict, List
from collections import defaultdict 
from queue import Queue
import os

configs=[]
shutdown_flag: bool = False
stop_flag: bool = True

client_id_map: Dict[int, str] = {} # Maps numerical IDs to client identifiers 
next_client_id: int = 1 # Counter for generating unique numerical IDs 
client_sockets: Dict[str, socket.socket] = {} # Each client has its own socket 
client_queues: Dict[str, Queue] = defaultdict(Queue) # Each client has its own queue

def signal_handler(signum: int, frame: Any) -> None:
    global shutdown_flag, stop_flag
    stop_flag = True
    save_configuration()
    print("\nShutdown signal received. Initiating graceful shutdown...")

def load_configuration():
    global configs
    # Check if the file exists
    if os.path.exists("data.json"):
        # If the file exists, load the data
        with open("data.json", "r") as json_file:
            configs = json.load(json_file)
            print("Service configuration data loaded successfully.")
    else:
        configs = [
            {
                'id': 1,
                'servers': [
                    {'address': 'oregon.com', 'port': 443, 'service_type': 'HTTPS', 'interval': 10},
                    {'address': 'facebook.com', 'port': 443, 'service_type': 'TCP', 'interval': 15}
                ]
            }
        ]

def save_configuration():
    print("\nSaving configuratio to data.json file...")
    # Saving the dictionary to a JSON file
    with open("data.json", "w") as json_file:
        json.dump(configs, json_file, indent = 4)
        print("Data saved succeccfully")

def create_message(action: str, data: Any = None) -> str: 
    message: Dict[str, Any] = {"type": action, "data": data} 
    return json.dumps(message)

def parse_message(message: str) -> Dict[str, Any]:
    return json.loads(message)

def handle_client_connection(client_socket: socket.socket, addr: str) -> None:
    global client_queues
    global shutdown_flag
    try:
        while not shutdown_flag:
            message_bytes: bytes = client_socket.recv(1024)
            if not message_bytes:
                break # Client closed connection
            message: str = message_bytes.decode('utf-8')
            parsed_message: Dict[str, Any] = parse_message(message) 
            # print (f"\n[Server] Message from {addr}: {parsed_message}")
            if parsed_message["type"] == "log":
                # Client requests server to create messages in its queue 
                print (f" [Server] {addr} :: {parsed_message.get('data', 'No Data')}")
            # Add more actions based on the parsed_message type as needed
    except socket.error as e:
        print (f"\n[Server] Socket error with {addr}: {e}")
    finally:
        client_socket.close()
        if addr in client_queues:
            del client_queues[addr]
        print(f"\n[Server] Connection with {addr} closed.")


def server_commands_interface() -> None:
    global shutdown_flag
    global configs
    # List of commands for auto-completion
    commands = [
        "viewconf", "addserver", "delserver", "queue_info", "list_clients", 
        "list_queue", "list_all_queues", "help", "exit"
    ]

    # Initialize the command completer with the list of commands 
    completer = WordCompleter (commands)

    # Create a PromptSession with the completer
    session = PromptSession(completer=completer)

    while not shutdown_flag:
        with patch_stdout():
            try:
                action = session.prompt("Server Command> ", wrap_lines=False)
                parts = action.split()
                cmd = parts[0] if parts else ""

                if cmd == "help":
                    print("\nAvailable server commands:")
                    print(" viewconf - View total configurations")
                    print(" viewconf <client_id> - View configuration for a specific client.")
                    print(" addconf <client_id> <ServerType> <URL> ... <TimeInterval>- Add configuration for a specific client.")
                    print("         HTTP, HTTPS, NDP -  ... is Nothing")
                    print("         TCP, UDP, LOCAL -  ... is <Port>")
                    print("         DNS -  ... is <Query> <Type>")
                    print("         ICMP -  ... is <Tools> (1 - ping, 2 - Tracerout)")
                    print(" delconf <client_id> <service_id>- Remove specific service for a specific client.")
                    print(" list_queue <client_id> - View specific client status")
                    print(" list_all_queues - View all clients' status")
                    print(" help - Display this help message.")
                    print(" exit - Exit the server application.")
                elif cmd == "exit":
                    shutdown_flag = True
                    print("\nExiting server application...")

                    # Close all client sockets and perform any necessary cleanup 
                    print(f"Closing {len(client_sockets)} client connections...") 
                    for sock in client_sockets.values():
                        try:
                            sock.close()
                        except Exception as e:
                            print(f"Error while closing client socket: {e}")
                    client_sockets.clear() # Clear the dictionary after closing all sockets
                    save_configuration() # Save the configuration data to data.json
                elif cmd == "list_clients":
                    print (f"\nConnected clients({len(client_id_map)}):")
                    for client_id, client_identifier in client_id_map.items(): 
                        print(f" {client_id}: {client_identifier}")
                elif cmd == "viewconf":
                    if  len(parts) == 2:
                        client_num_id = int(parts[1])
                        client_identifier = client_id_map.get(client_num_id)
                        desired_item = None
                        for config in configs:
                            if config['id'] == client_num_id:
                                desired_item = config
                                break
                        if desired_item:
                            for server_config in desired_item["servers"]:
                                print(server_config)
                        else:
                            print(f"Configuration data with id={client_num_id} not found.")
                    else:
                        for config in configs:
                            print (f"------Client {config['id']}-------")
                            for server_config in config["servers"]: 
                                print (server_config)
                elif cmd == "addconf" and len(parts) >= 5:
                    client_num_id = int(parts[1]) 
                    client_identifier = client_id_map.get(client_num_id)
                    service_type = parts[2].upper()
                    if service_type in ["HTTP", "HTTPS", "NTP"] and len(parts) == 5:
                        config_data = {
                            'service_type': service_type,
                            'address': parts[3],
                            'interval': int(parts[4])
                        }
                    elif service_type in ["TCP",  "UDP"] and len(parts) == 6:
                        config_data = {
                            'service_type': service_type,
                            'address': parts[3],
                            'port': parts[4],
                            'interval': int(parts[5])
                        }
                    elif service_type in ["ICMP"] and len(parts) == 6:
                        config_data = {
                            'service_type': service_type,
                            'address': parts[3],
                            'tool': parts[4],
                            'interval': int(parts[5])
                        }
                    elif service_type in ["LOCAL"] and len(parts) == 6:
                        config_data = {
                            'service_type': 'Local TCP Server',
                            'address': parts[3],
                            'tool': parts[4],
                            'interval': int(parts[5])
                        }
                    elif service_type in ["DNS"] and len(parts) == 7:
                        config_data = {
                            'service_type': service_type,
                            'address': parts[3],
                            'query': parts[4],
                            'record_type': parts[5],
                            'interval': int(parts[5])
                        }
                    else:
                        break
                    desired_item_index = -1
                    for index, config in enumerate(configs):
                        if config['id'] == client_num_id:
                            desired_item_index = index
                            break
                    if desired_item_index > -1:
                        configs[desired_item_index]['servers'].append(config_data)
                    else:
                        configs.append({
                            'id': client_num_id,
                            'servers': [config_data]
                        })
                        desired_item_index = 0
                    print (f"configuration data added to the client {client_num_id}")
                    if client_identifier:
                        response_message = create_message( "configuration", data=configs[desired_item_index]['servers']) 
                        client_sockets[client_identifier].send(response_message.encode('utf-8'))
                        print (f"updated configuration data sent to the client {client_identifier}")
                elif cmd == "removeconf" and len(parts) == 3:
                    client_num_id = int(parts[1]) 
                    client_identifier = client_id_map.get(client_num_id)
                    conf_id = int(parts[2]) 
                    desired_item_index = -1
                    for index, config in enumerate(configs):
                        if config['id'] == client_num_id:
                            desired_item_index = index
                            break
                    if desired_item_index > -1:
                        if len(configs[desired_item_index]['servers']) >= conf_id:
                            del configs[desired_item_index]['servers'][conf_id-1]
                            print (f"configuration data removed to the client {client_num_id}")
                            response_message = create_message( "configuration", data=configs[desired_item_index]['servers']) 
                            if client_identifier:
                                client_sockets[client_identifier].send(response_message.encode('utf-8'))
                                print (f"updated configuration data sent to the client {client_identifier}")
                        else:
                            print(f"There is no config data on the client {client_identifier}, service {conf_id}")
                    else:
                        print(f"Configuration data with id={client_num_id} not found.")
                elif cmd == "list_queue" and len(parts) == 2:
                    num_id = int(parts[1])
                    client_identifier = client_id_map.get(num_id)
                    if client_identifier and client_identifier in client_queues:
                        queue_contents = list(client_queues[client_identifier].queue)
                        print(f"\nQueue for client ID {num_id} ({client_identifier}): {len(num_id)} services") 
                        for item in queue_contents:
                            print(f" {item}")
                    else:
                        print(f"\nNo queue found for client ID {num_id}.")

                elif cmd == "list_all_queues":
                    print("\nAll client queues:")
                    for num_id, client_identifier in client_id_map.items():
                        queue_contents = list(client_queues[client_identifier].queue)
                        print(f" Client ID {num_id} ({client_identifier}): {len(configs[num_id])} services")
                        for item in queue_contents:
                            print (f" {item}")
            except Exception as e:
                print(f"Error in server command interface: {e}")
    print("\nServer command interface closed.")

def start_server() -> None:
    global shutdown_flag
    global client_id_map
    global next_client_id
    host: str = 'localhost'
    port: int = 54321
    server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    server_socket.settimeout(1.0)
    
    print(f" [Server] Server listening on {host}:{port}")
    
    if stop_flag:
        command_thread: threading.Thread = threading.Thread(target=server_commands_interface, daemon=True) 
        command_thread.start()
    try:
        while not shutdown_flag:
            try:
                client_socket, addr = server_socket.accept()
                # Assign a numerical ID to the client
                client_id = next_client_id
                next_client_id += 1
                for config in configs:
                    if config['id'] == client_id:
                        desired_item = config
                        break
                else:
                    desired_item = configs[0]

                print (f"\n[Server] Accepted connection from {addr}")
                client_identifier = str(addr) # Convert the address tuple to a string

                response_message = create_message( "configuration", data=desired_item['servers']) 
                client_socket.send(response_message.encode('utf-8'))
                
                # Use the client's address as a unique identifier
                client_id_map[client_id] = client_identifier 
                client_sockets[client_identifier] = client_socket 
                client_queues[client_identifier] = Queue()

                client_thread: threading.Thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_identifier), daemon=True) 
                client_thread.start()
            except socket.timeout:
                continue # Go back to the start of the while loop to check shutdown_flag again
            except Exception as e:
                print(f"\n[Server] Error in server loop: {e}")
        print("\n[Server] Server shutdown initiated.")
    finally:
        server_socket.close()
        print("\n[Server] Server shutdown gracefully.")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler) 
    signal.signal(signal.SIGTERM, signal_handler)
    load_configuration()
    start_server()



