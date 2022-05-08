import socket
import os
# TCP Client
def anonfs_interface(host, port, restore=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        cwd = os.getcwd()
        file_path = os.path.join(cwd,"messages.log")
        if(restore):
            # load checksum from file
            checksum = open("checksum.txt","r").read()
            s.send(f"download {file_path} {checksum}\n".encode())
        else: 
            s.send(f"upload {file_path}\n".encode())
            checksum = s.recv(1024)
            # save checksum to file
            with open("checksum.txt", "w") as f:
                f.write(checksum.decode())
            # get checksum from file
            with open("checksum.txt", "r") as f:
                checksum_file = f.read()



            
            