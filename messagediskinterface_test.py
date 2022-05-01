import unittest
import os
import anoncrypto as cp
from MessageDiskInterface import MessageDiskInterface
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5

#create the test class
class MessageDiskInterfaceTest(unittest.TestCase):
    
    #create class initalizer
    def setUp(self):
        pass
        #create a new message disk interface
        # db={}
        # self.mdi = MessageDiskInterface(db,askey.private_key,"test_messages.log")
    # test verifyDecrypt

    def test_verifyDecrypt(self):
        # Key generation
        if(os.path.exists("test_messages.log")):
            os.remove("test_messages.log")
        db={}
        askey = cp.AnonKeys(file_name="userkey.pickle")
        askey2 = cp.AnonKeys(file_name="userkey_test.pickle")
        askey.get_RSA_key()
        askey2.get_RSA_key()
        self.mdi = MessageDiskInterface(db,askey.private_key,"test_messages.log")
        #create a message
        message = "Hello World".encode()
        #encrypt the message
        cipher = Cipher_PKCS1_v1_5.new(askey.public_key)
        ciphertext = cipher.encrypt(message)
        signature = cp.sign(askey2.private_key, ciphertext)
        #verify the message
        self.assertTrue(self.mdi.verifyDecrypt(ciphertext,signature,askey2.public_key) == message)
    # test addEntry

    def test_addEntry(self):
        # Key generation
        # remove file test_messages.log
        if(os.path.exists("test_messages.log")):
            os.remove("test_messages.log")
        db={}
        askey = cp.AnonKeys(file_name="userkey.pickle")
        askey.load_RSA_key()
        self.mdi = MessageDiskInterface(db,askey.private_key,"test_messages.log")
        priv_gen,pub_gen=askey.generate_RSA_key()
        #create a message
        message = "Hello World".encode()
        #encrypt the message
        cipher = Cipher_PKCS1_v1_5.new(askey.public_key)
        ciphertext = cipher.encrypt(message)
        signature = cp.sign(priv_gen, ciphertext)
        #add the message to the database
        ip = "127.0.0.1"
        self.mdi.addEntry(pub_gen,ip,ciphertext,signature,False)
        #check that the message is in the database
        self.assertTrue(self.mdi.db[ip]["pubkey"] == pub_gen)
        self.assertTrue(ciphertext in self.mdi.db[ip]["messages"][0]["enc_message"])



if __name__ == '__main__':
    unittest.main()