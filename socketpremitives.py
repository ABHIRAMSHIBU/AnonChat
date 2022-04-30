import socket
import anoncrypto as cp
import pickle
from Crypto.PublicKey import RSA


class CommUtils:
    def __init__(self, db, askey, HOST):
        self.db = db
        self.askey = askey
        self.HOST = HOST

    def insertDB(self, dec_message, public_key, torurl):
        if(torurl not in self.db):
            self.db[torurl] = {"messages": [], "pubkey": public_key}
        self.db[torurl]["messages"].append(dec_message)

    def process_message(self, data):
        # Format [torurl,enc_message,signature,public_key]
        data = pickle.loads(data)
        print(data)
        torurl, enc_message, signature, public_key = data
        public_key = RSA.import_key(public_key)
        if(cp.verify(enc_message, signature, public_key)):
            dec_message = cp.decrypt(self.askey.private_key, enc_message)
            print(dec_message)
            self.insertDB(dec_message, public_key, torurl, self.db)
            print("Done!")
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
                        if(self.process_message(data, self.db)):
                            conn.send(b"Success")
                        else:
                            conn.send(b"Failure")
        except KeyboardInterrupt:
            print("Bye..")
        except Exception as e:
            print(e)
            return False

    def send_message(self, public_key, torurl, message):
        remote_host = torurl  # URL for reciver
        PORT = 9999   # Port for AnonChat on reciever
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((remote_host, PORT))
            enc_message = cp.encrypt(public_key, message.encode())
            signature = cp.sign(self.askey.private_key, enc_message)
            s.send(pickle.dumps(
                [self.HOST, enc_message, signature, public_key.export_key()]))
            s.close()
