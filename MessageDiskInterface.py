import pickle
from Crypto.PublicKey import RSA
import base64
import anoncrypto as cp



class MessageDiskInterface:
    ''' 
    Should handle database totally as well as the storage of it create this class's object with db, private key, storage file as arguments
    '''
    def __init__(self,db,hostPriv,file="messages.log"):
        '''
        db: database of messages
        hostPriv: private key of host
        file: file to store messages
        '''
        self.db = db
        self.f = open(file,"a+")
        self.f.seek(0)
        self.loadEntries()        
        self.hostPriv = hostPriv

    def addEntry(self,public_key,ip,enc_message,signature,send=False):
        '''
        public_key: public key of sender
        ip: ip of sender
        enc_message: encrypted message
        signature: signature of message
        send: whether message is sent or received
        '''
        # self.f.write(public_key.exportKey().decode())
        # self.f.write(":")
        # self.f.write(ip)
        # self.f.write(":")
        # self.f.write(enc_message.decode())
        # self.f.write(":")
        # self.f.write(signature.decode())
        # U know what? let's do pickle implementation
        # base64 encode before writing pickle
        self.f.write(base64.encodebytes(pickle.dumps([public_key.export_key().decode(),ip,enc_message,signature,send])).decode())
        if(ip not in self.db):
            self.db[ip] = {"messages": [], "pubkey": public_key}
        self.db[ip]["pubkey"] = public_key
        self.db[ip]["messages"].append({"enc_message":enc_message,"signature":signature,"send_bool":send})        
        self.f.write("\n")
        self.f.flush()

    def verifyDecrypt(self,enc_message,signature,sender_public_key):
        '''
        cp: CryptoPrimitives object (for verification and decryption)
        enc_message: encrypted message
        signature: signature of message
        sender_public_key: public key of sender - Imported key
        '''
        if(cp.verify(sender_public_key, signature, enc_message)):
            if(self.hostPriv is None):
                print("Warning: DiskInterface.py: Private key is None")
            if(enc_message is None):
                print("Warning: DiskInterface.py: Encrypted message is None")
            dec_message = cp.decrypt(self.hostPriv, enc_message)
            return dec_message
        else:
            return None

    def loadEntries(self):
        '''
        Loads all the entries from the file in database
        '''
        for line in self.f:
            data = pickle.loads(base64.decodebytes(line.encode()))
            if(len(data)<5):
                print("MessageDiskInterface.py:Invalid data in file")
                continue
            data[0] = RSA.import_key(data[0])
            self.db[data[1]] = {"messages": [], "pubkey": data[0]}
            # Todo add support for time also..
            # New way encrypted message,signature
            self.db[data[1]]["messages"].append({"enc_message":data[2],"signature":data[3],"send_bool":data[4]})
    
    def __del__(self):
        '''
        Destructor
        '''
        self.f.close()