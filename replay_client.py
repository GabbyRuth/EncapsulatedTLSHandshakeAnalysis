import socket
import time
import ssl
from scapy.all import PcapReader, IP, TCP, UDP

def establish_tls_connection(host, port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.settimeout(10)  # Set a timeout on the socket

    tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
    try:
        tls_socket.connect((host, port))
        print(f"Connected to server with TLS at {host}:{port}.")
        return tls_socket
    except Exception as e:
        print(f"Error during TLS connection: {e}")
        return None

def process_packet(packet, start_time, client_socket, first_packet_time):
    elapsed = time.time() - start_time
    packet_time = packet.time - first_packet_time
    
    # Time synchronization
    if packet_time > elapsed:
        time.sleep(packet_time - elapsed)
    
    # Check for TCP or UDP layer and payload
    protocol_layer = None
    if packet.haslayer(TCP):
        protocol_layer = TCP
    elif packet.haslayer(UDP):
        protocol_layer = UDP
    
    if protocol_layer and packet[protocol_layer].payload:
        data = bytes(packet[protocol_layer].payload)
        print(f"Processing packet at time: {packet.time}")
        try:
            print(f"Sending {len(data)} bytes of data.")
            client_socket.sendall(data)
            print("Data sent successfully.")
        except socket.error as e:
            print("Socket error:", e)
        except Exception as e:
            print("An error occurred:", e)
    else:
        print(f"Packet at time {packet.time} does not contain TCP/UDP payload.")

def main():
    # User input for the .pcap file, chunk size, and number of batches
    pcap_file = input("Enter the path to the .pcap file: ")
    chunk_size = int(input("Enter the number of payloads (chunk size): "))
    num_batches = int(input("Enter the number of batches to run: "))

    # Configuration for the relay server
    HOST = '127.0.0.1'
    PORT = 1080

    # Establish TLS connection
    client_socket = establish_tls_connection(HOST, PORT)
    if client_socket is None:
        print("Failed to establish TLS connection.")
        return

    try:
        # Calculate the total number of packets to process
        total_packets_to_process = chunk_size * num_batches
        packet_count = 0

        # Process and replay the pcap file in chunks
        print("Reading pcap in chunks...")
        start_time = time.time()
        first_packet_time = None
        with PcapReader(pcap_file) as pcap_reader:
            print("PcapReader opened.")
            batch = []
            for packet in pcap_reader:
                if first_packet_time is None:
                    first_packet_time = packet.time
                    print("First packet time recorded.")

                batch.append(packet)
                if len(batch) == chunk_size:
                    print(f"Processing a batch of {chunk_size} packets...")
                    for pkt in batch:
                        process_packet(pkt, start_time, client_socket, first_packet_time)
                    print(f"Batch processed.")
                    batch = []
                    packet_count += chunk_size

                    # Break out of the loop after processing the specified number of batches
                    if packet_count >= total_packets_to_process:
                        print(f"Processed {num_batches} batches. Exiting.")
                        break

            # Process any remaining packets if we haven't reached the total
            if batch and packet_count < total_packets_to_process:
                print(f"Processing final batch of {len(batch)} packets...")
                for pkt in batch:
                    process_packet(pkt, start_time, client_socket, first_packet_time)
                print("Final batch processed.")

    finally:
        print("Closing TLS connection.")
        client_socket.close()

if __name__ == "__main__":
    main()

