import socket

from zmq import Message
from MessageDiskInterface import MessageDiskInterface
import anoncrypto as cp
import pickle
import traceback
from Crypto.PublicKey import RSA


class CommUtils:
    def __init__(self, db, askey, mdi: MessageDiskInterface , HOST):
        '''
        db: database of messages
        askey: Asymmetric key manager object
        mdi: MessageDiskInterface object
        HOST: Hostname of host
        '''
        self.db = db
        self.askey = askey
        self.HOST = HOST
        self.mdi = mdi

    # def insertDB(self, dec_message, public_key, torurl):
    #     if(torurl not in self.db):
    #         self.db[torurl] = {"messages": [], "pubkey": public_key}
    #     self.db[torurl]["messages"].append(dec_message)

    def process_message(self, data, peer_host_port):
        # Format [torurl,enc_message,signature,public_key]
        data = pickle.loads(data)
        # print(data)
        torurl, enc_message, signature, public_key = data
        public_key = RSA.import_key(public_key)
        if(cp.verify(public_key, signature, enc_message)):
            # TODO: Change this to use self.mdi.verifyDecrypt
            dec_message = cp.decrypt(self.askey.private_key, enc_message)
            print("\r    "+"\r"+dec_message.decode()+"\n"+"You:", end="")
            # print > in the next line and take input from same line
            self.mdi.addEntry(torurl,peer_host_port[0],enc_message,signature,False)
            # self.insertDB(dec_message, public_key, torurl)
            # print("Done!")
            return True
        else:
            print("Verification Failure")
            return False

    # Python Server
    def receiver_function(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("0.0.0.0", 9999))
            s.listen()
            while True:
                conn, addr = s.accept()
                with conn:
                    # TODO: Threading might give better performance
                    while True:
                        # Assuming 1024 bytes as max message size
                        data = conn.recv(1024)
                        if not data:
                            break
                        if(self.process_message(data,conn.getpeername())):
                            conn.send(b"Success")
                        else:
                            conn.send(b"Failure")
        except KeyboardInterrupt:
            print("Bye..")
        except Exception as e:
            print(e)
            # print stack trace
            traceback.print_exc()
            return False

    def send_message(self, self_public_key, reciever_public_key, torurl, message):
        remote_host = torurl  # URL for reciver
        PORT = 9999   # Port for AnonChat on reciever
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((remote_host, PORT))
            # Encrypt the message with reciever's public key
            enc_message = cp.encrypt(reciever_public_key, message.encode())
            # Sign the message with our private key
            signature = cp.sign(self.askey.private_key, enc_message)
            self.mdi.addEntry(torurl,remote_host,enc_message,signature,True)
            s.send(pickle.dumps(
                [self.HOST, enc_message, signature, self_public_key.export_key()]))
            s.close()
