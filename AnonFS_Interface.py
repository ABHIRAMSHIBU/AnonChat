import socket
import os
# TCP Client
def anonfs_interface(host, port, restore=False):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        cwd = os.getcwd()
        file_path = os.path.join(cwd,"messages.log")
        if(restore):
            print("Restore Request Received")
            # load checksum from file
            checksum = open("checksum.txt","r").read()
            # log
            print("Checksum:",checksum)
            print("Sending "+f"download {file_path} {checksum}")
            s.send(f"download {file_path} {checksum}\n".encode())
            print("Waiting for DONE Acknowledgement")
            data = s.recv(1024).decode()
            if(data == "DONE"):
                print("Restore Successful")
            else:
                print("Restore Failed")
        else: 
            # print("Upload Request Received")
            s.send(f"upload {file_path}\n".encode())
            # print("Upload Request Completed")
            checksum = s.recv(1024)
            # print("Received Checksum:",checksum)
            # save checksum to file
            with open("checksum.txt", "w") as f:
                f.write(checksum.decode())
            # print("Checksum Saved")
            