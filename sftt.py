import tkinter as tk
from tkinter import filedialog , ttk
import socket
import threading
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import struct
import time

# Function to derive a cryptographic key from a password
def derive_key(password):
    salt = b'sal_t'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file using AES-CBC mode
def pad_data(data):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Function to decrypt a file using AES-CBC mode
def unpad_data(data):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Function to send a file over a socket connection
def send_file(sock, filename, password):
    try:
        start_time = time.time()
        key = derive_key(password)
        with open(filename, 'rb') as file:
            total_size = os.path.getsize(filename)
            sent_size = 0

            file_data = file.read()
            file_data = pad_data(file_data)

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()

            fn_bytes = os.path.basename(filename).encode()

            # Send file metadata: filename length, filename, total size, and IV
            sock.sendall(struct.pack('I', len(fn_bytes)) + fn_bytes)
            sock.sendall(struct.pack('Q', len(encrypted_data)))
            sock.sendall(iv)
            chunk_size = 8192  # 8 KB chunk size
            for i in range(0, len(encrypted_data), chunk_size):
                chunk = encrypted_data[i:i + chunk_size]
                sock.sendall(chunk)
                sent_size += len(chunk)
                progress = (sent_size / len(encrypted_data)) * 100
                progress_bar['value'] = progress
                progress_label.config(text=f"Progress: {int(progress)}%")
                root.update_idletasks()

        end_time = time.time()
        elapsed_time = end_time - start_time
        transfer_speed = (total_size / elapsed_time) * 8 / (1024 * 1024)
        return transfer_speed
    except FileNotFoundError:
        status_label.config(text="Error: File not found.", fg="red")
    except ConnectionResetError:
        status_label.config(text="Connection was forcibly closed by the remote host.", fg="red")
    except socket.gaierror:
        status_label.config(text="Invalid host or port.", fg="red")
    except ConnectionRefusedError:
        status_label.config(text="Connection refused. Check host and port.", fg="red")
    except socket.timeout:
        status_label.config(text="Connection timed out. The host did not respond.", fg="red")
    except TimeoutError:
        status_label.config(text="Connection timed out. Check host and port.", fg="red")
    except ConnectionError as e:
        status_label.config(text=f"Error: Connection failed. {e}", fg="red")
    except Exception as e:
        status_label.config(text=f"Error during file transfer: {e}", fg="red")
    finally:
        if 'sock' in locals():
            sock.close()
    return None

# Function to decrypt data using AES-CBC mode and a key derived from a password
def decrypt_data(key, data):
    iv = data[:16]
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpad_data(decrypted_data)
    return unpadded_data

# Function to receive a file over a socket connection and decrypt it using a key derived from a password
def receive_file(client_socket, key):
    try:
        start_time = time.time()
        filename_len = struct.unpack('I', client_socket.recv(4))[0]
        filename = client_socket.recv(filename_len).decode()
        total_size = struct.unpack('Q', client_socket.recv(8))[0]
        iv = client_socket.recv(16)

        encrypted_data = b""
        received_size = 0

        while received_size < total_size:
            chunk = client_socket.recv(8192)
            if not chunk:
                raise ConnectionError("Connection interrupted during file transfer.")
            encrypted_data += chunk
            received_size += len(chunk)
            progress = (received_size / total_size) * 100
            progress_bar['value'] = progress
            progress_label.config(text=f"Progress: {int(progress)}%")
            root.update_idletasks()

        try:
            decrypted_data = decrypt_data(key, iv + encrypted_data)
            with open(filename, 'wb') as file:
                file.write(decrypted_data)
                end_time = time.time()
                transfer_time = end_time - start_time
                transfer_speed = (total_size / transfer_time) * 8 / (1024 * 1024)
                return transfer_speed
        except ValueError as e:
            print(f"Decryption failed: {e}")
            status_label.config(text="Check the password and try again!", fg="red")
        except IOError as e:
            print(f"File write error: {e}")
            status_label.config(text=f"File write error: {e}", fg="red")

    except ConnectionError as e:
        print(f"Error: {e}")
        status_label.config(text=f"Disconnected: {e}", fg="red")
    except Exception as e:
        print(f"Error during file reception: {e}")
        status_label.config(text=f"Error: {e}", fg="red")

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

def toggle_password_visibility():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_button.config(text='Hide')
    else:
        password_entry.config(show='*')
        toggle_button.config(text='Show')

def update_host_field_state():
    if mode_var.get() == "receive":
        host_entry.config(state="disabled")
        choose_file_button.config(state="disabled")
    else:
        host_entry.config(state="normal")
        choose_file_button.config(state="normal")

def send_files_threaded():
    threading.Thread(target=send_files_gui).start()
def receive_file_threaded():
    threading.Thread(target=receive_file_gui).start()

def update_execute_button_text(*args):
    if mode_var.get() == "send":
        execute_button.config(text="Transfer", command=send_files_threaded)
    else:
        execute_button.config(text="Connect", command=receive_file_threaded)

# GUI functions to send and receive files
def send_files_gui():
    password = password_entry.get()
    host = host_entry.get()
    port = port_entry.get()
    filenames = file_path_label.cget("text")
    progress_bar['value'] = 0
    status_label.config(text="")
    if not (password and filenames and host and port):
        status_label.config(text="Please fill in all fields!", fg="red")
        return
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            status_label.config(text="Invalid port number. Must be between 1 and 65535.", fg="red")
            return
    except ValueError:
        status_label.config(text="Invalid port number. Must be a number.", fg="red")
        return
    try:
        sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sender_socket.settimeout(5)
        status_label.config(text="Connecting...", fg="yellow")
        root.update_idletasks()
        sender_socket.connect((host, port))
        status_label.config(text="Sending file...", fg="yellow")
        root.update_idletasks()
        transfer_speed = send_file(sender_socket, filenames, password)
        status_label.config(text=f"Files sent successfully! Speed: {transfer_speed:.2f} Mb/s", fg="green")
    except Exception as e:
        status_label.config(text=f"Error : {str(e)}", fg="red")
    finally:
        if 'sender_socket' in locals():
            sender_socket.close()


def receive_file_gui():
    global running
    receiver_socket = None
    key = password_entry.get()
    progress_bar['value'] = 0
    status_label.config(text="")

    try:
        port = int(port_entry.get())
        if not (1 <= port <= 65535):
            raise ValueError("Invalid port number. Must be between 1 and 65535.")
    except ValueError as e:
        status_label.config(text=f"Error: {e}", fg="red")
        return

    if not key:
        status_label.config(text="Please enter a valid key and port!", fg="red")
        return

    def listen_for_connections():
        nonlocal receiver_socket
        try:
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            receiver_socket.bind(('0.0.0.0', port))
            receiver_socket.listen(1)
            root.after(0, lambda: status_label.config(text="Listening for connections...", fg="yellow"))

            while running:
                try:
                    receiver_socket.settimeout(1)  # 1-second timeout
                    client_socket, client_address = receiver_socket.accept()
                    print(f"Connection established with: {client_address}")
                    root.after(0, lambda: status_label.config(text="Receiving file...", fg="yellow"))
                    transfer_speed = receive_file(client_socket, derive_key(key))
                    client_socket.close()
                    if transfer_speed:
                        root.after(0, lambda: status_label.config(text=f"File received successfully! Speed: {transfer_speed:.2f} Mb/s", fg="green"))
                    else:
                        root.after(0, lambda: status_label.config(text="Failed to recieve file!", fg="red"))
                except socket.timeout:
                    continue  # Allow loop to check `running` flag
                except Exception as e:
                    print(f"Error during file reception: {e}")
                    root.after(0, lambda: status_label.config(text=f"Error: {e}", fg="red"))
                    break
        except OSError as e:
            if running:  # Only show errors if not shutting down
                root.after(0, lambda: status_label.config(text=f"Socket error: {e}", fg="red"))
        except Exception as e:
            root.after(0, lambda: status_label.config(text=f"Unexpected error: {e}", fg="red"))
        finally:
            try:
                if receiver_socket:
                    receiver_socket.close()
            except Exception as e:
                print(f"Error during cleanup: {e}")
            print("Receiver socket closed.")

    def on_closing():
        global running
        running = False  # Stop the loop
        try:
            if receiver_socket:
                receiver_socket.close()
        except Exception as e:
            print(f"Error closing receiver socket: {e}")
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    running = True
    listener_thread = threading.Thread(target=listen_for_connections, daemon=True)
    listener_thread.start()

def choose_files():
    progress_bar['value'] = 0
    status_label.config(text="")
    filename = filedialog.askopenfilename()
    file_path_label.config(text=filename)
    if filename:
        execute_button.config(state="normal")
    else:
        execute_button.config(state="disabled")

def update_progress_bar(value):
    progress_bar['value'] = value
    progress_label.config(text=f"Progress: {int(value)}%")
    root.update_idletasks()

# GUI setup
root = tk.Tk()
root.title("Secure File Transfer Tool")
root.geometry('300x650')
root.configure(bg='#282c34')

header_label = tk.Label(root, text="Secure File Transfer Tool", font=("Helvetica", 16, "bold"), bg="#61afef", fg="#282c34", pady=10)
header_label.pack(fill=tk.X)

mode_frame = tk.Frame(root, bg='#282c34')
mode_frame.pack(pady=10)
mode_label = tk.Label(mode_frame, text="Select Mode:", bg='#282c34', fg='white', font=("Helvetica", 12))
mode_label.pack(side=tk.LEFT, padx=10)
mode_var = tk.StringVar(value="send")
send_radio = tk.Radiobutton(mode_frame, text="Send", variable=mode_var, value="send", bg='#282c34', fg='white', selectcolor='#61afef', command=update_host_field_state)
receive_radio = tk.Radiobutton(mode_frame, text="Receive", variable=mode_var, value="receive", bg='#282c34', fg='white', selectcolor='#61afef', command=update_host_field_state)
send_radio.pack(side=tk.LEFT, padx=5)
receive_radio.pack(side=tk.LEFT, padx=5)

ip_frame = tk.Frame(root, bg='#282c34')
ip_frame.pack(pady=5, padx=20, fill=tk.X)
ip_label = tk.Label(ip_frame, text="Your IP: ", bg='#282c34', fg='white', font=("Helvetica", 12))
ip_label.pack(side=tk.LEFT)
ip_address_label = tk.Label(ip_frame, text=get_ip(), bg='#282c34', fg='white', font=("Helvetica", 12))
ip_address_label.pack(side=tk.LEFT, padx=5)

host_label = tk.Label(root, text="Enter Host:", bg='#282c34', fg='white', font=("Helvetica", 12))
host_label.pack(pady=5)
host_entry = tk.Entry(root, font=("Helvetica", 12))
host_entry.pack(pady=5, padx=20, fill=tk.X)

port_label = tk.Label(root, text="Enter Port:", bg='#282c34', fg='white', font=("Helvetica", 12))
port_label.pack(pady=5)
port_entry = tk.Entry(root, font=("Helvetica", 12))
port_entry.pack(pady=5, padx=20, fill=tk.X)

password_label = tk.Label(root, text="Enter Password/Key:", bg='#282c34', fg='white', font=("Helvetica", 12))
password_label.pack(pady=5)
password_frame = tk.Frame(root, bg='#282c34')
password_frame.pack(pady=5, padx=20, fill=tk.X)
password_entry = tk.Entry(password_frame, show="*", font=("Helvetica", 12))
password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
toggle_button = tk.Button(password_frame, text="Show", command=toggle_password_visibility, bg='#61afef', fg='#282c34', font=("Helvetica", 10, "bold"))
toggle_button.pack(side=tk.RIGHT, padx=5)

file_label = tk.Label(root, text="File (Send Mode Only):", bg='#282c34', fg='white', font=("Helvetica", 12))
file_label.pack(pady=5)
file_path_label = tk.Label(root, text="No file chosen", bg='#44475a', fg='white', font=("Helvetica", 10), anchor="w")
file_path_label.pack(pady=5, padx=20, fill=tk.X)
choose_file_button = tk.Button(root, text="Choose Files", command=choose_files, bg='#61afef', fg='#282c34', font=("Helvetica", 10, "bold"))
choose_file_button.pack(pady=5)

execute_button = tk.Button(root, text="", bg='#98c379', fg='#282c34', font=("Helvetica", 12, "bold"))
execute_button.pack(pady=20)

progress_bar = ttk.Progressbar(root, orient='horizontal', mode='determinate', length=280)
progress_bar.pack(pady=10)
progress_label = tk.Label(root, text="Progress: 0%", bg='#282c34', fg='white', font=("Helvetica", 10))
progress_label.pack(pady=5)

status_label = tk.Label(root, text="", bg='#282c34', fg='white', font=("Helvetica", 10))
status_label.pack(pady=10)

mode_var.trace("w", update_execute_button_text)
update_execute_button_text()
update_host_field_state()
root.mainloop()