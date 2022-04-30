import os
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256


class AnonKeys:
    def __init__(self, file_name):
        self.file_name = file_name
        self.private_key, self.public_key = None, None

    def generate_RSA_key(self):
        keys = RSA.generate(2048)
        pub = RSA.import_key(keys.public_key().export_key('DER'))
        prv = RSA.import_key(keys.export_key('DER'))
        self.private_key = prv
        self.public_key = pub
        return prv, pub

    def load_RSA_key(self):
        if(os.path.exists(self.file_name)):
            try:
                f = open(self.file_name, "rb")
                prv, pub = pickle.load(f)
                prv = RSA.import_key(prv)
                pub = RSA.import_key(pub)
                self.private_key = prv
                self.public_key = pub
                return prv, pub
            except Exception as e:
                print(e)
                return None
        else:
            return None

    def save_RSA_key(self):
        with open(self.file_name, "wb") as keyfile:
            pickle.dump([self.private_key.export_key(),
                        self.public_key.export_key()], keyfile)
            print("Write success")
        return True

    def get_RSA_key(self):
        # if the file exists, load the key
        if(os.path.exists(self.file_name)):
            return self.load_RSA_key()
        else:
            return self.generate_RSA_key()


def encrypt(key, data):
    enc_data = Cipher_PKCS1_v1_5.new(key).encrypt(data)
    return enc_data


def decrypt(key, enc_data):
    '''
    Params
        key - Key for decryption of message
        enc - Encrypted message
    '''
    data = Cipher_PKCS1_v1_5.new(key).decrypt(enc_data, None)
    return data


def sign(keypair, data):
    digest = SHA256.new(data)
    signer = PKCS115_SigScheme(keypair)
    signature = signer.sign(digest)
    return signature


def verify(publickey, signature, enc_message):
    '''
    Params
        enc_message - Encrypted Message to be verified.
        signature - Signature of the message.
        publickey - Public of the Private key used to create signature
    '''
    digest = SHA256.new(enc_message)
    verifier = PKCS115_SigScheme(publickey)
    try:
        verifier.verify(digest, signature)
        return True
    except:
        return False
