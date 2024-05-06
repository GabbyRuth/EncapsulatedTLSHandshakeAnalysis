import socket

def replay_server():
    HOST = '127.0.0.1'  # The server's IP address
    PORT = 1083         # The server's port

    print(f"Replay server listening on {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected to by {addr[0]}:{addr[1]}")

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received data of size {len(data)} bytes.")
                
                # Echo the received data back to the client
                conn.sendall(data)
                print("Echoed data back to the client.")

def main():
    try:
        replay_server()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
