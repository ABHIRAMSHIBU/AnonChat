import unittest
import os
from anoncrypto import AnonKeys, decrypt, encrypt, sign, verify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5


class AnonCryptoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This function is executed once before all the tests
        print("Beginning Test Class")
        cls.file_name = "test_key.pkl"
        cls.anon_keys = AnonKeys(cls.file_name)

    def test_generate_RSA_key(self):
        print("Testing generate_RSA_key()")
        private_key, public_key = self.anon_keys.generate_RSA_key()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_save_load_RSA_key(self):
        print("Testing save_RSA_Key and load_RSA_key")
        # delete the file
        if(os.path.exists(self.file_name)):
            os.remove(self.file_name)
        self.anon_keys.generate_RSA_key()
        generated_private_key_encoded, generated_public_key_encoded = self.anon_keys.private_key.exportKey(
        ), self.anon_keys.public_key.exportKey()
        self.anon_keys.save_RSA_key()
        loaded_private_key, loaded_public_key = self.anon_keys.load_RSA_key()
        self.assertIsNotNone(loaded_private_key)
        self.assertIsNotNone(loaded_public_key)
        # check if anon_keys.private_key and anon_keys.public_key are the same as loaded_private_key and loaded_public_key
        generated_private_key = RSA.import_key(generated_private_key_encoded)
        generated_public_key = RSA.import_key(generated_public_key_encoded)

        # encrypt a message using generated_public_key
        cipher = Cipher_PKCS1_v1_5.new(generated_public_key)
        ciphertext = cipher.encrypt(b"Hello World")
        # decrypt the ciphertext using loaded_private_key
        cipher = Cipher_PKCS1_v1_5.new(loaded_private_key)
        plaintext = cipher.decrypt(ciphertext, None)
        self.assertEqual(plaintext, b"Hello World")

        self.assertEqual(generated_private_key, loaded_private_key)
        self.assertEqual(generated_public_key, loaded_public_key)
        self.assertNotEqual(generated_private_key, generated_public_key)
        self.assertNotEqual(loaded_private_key, loaded_public_key)

    def test_get_RSA_key(self):
        self.anon_keys.get_RSA_key()
        # check that the keys are not null
        self.assertIsNotNone(self.anon_keys.private_key)
        self.assertIsNotNone(self.anon_keys.public_key)

    def test_encrypt_decrypt(self):
        if(os.path.exists(self.file_name)):
            os.remove(self.file_name)
        # generate a key
        self.anon_keys.get_RSA_key()
        message = "Hello World"
        # encrypt a message
        encrypted_data = encrypt(self.anon_keys.public_key, message.encode())
        # decrypt the message
        decrypted_data = decrypt(self.anon_keys.private_key, encrypted_data)
        self.assertEqual(decrypted_data.decode(), message)

    def test_sign_verify(self):
        self.anon_keys.get_RSA_key()
        message = "Hello World"
        # encrypt the message
        encrypted_data = encrypt(self.anon_keys.public_key, message.encode())
        signature = sign(self.anon_keys.private_key, encrypted_data)
        # verify the signature
        verified = verify(self.anon_keys.public_key, signature, encrypted_data)
        self.assertTrue(verified)

    # teardown
    @classmethod
    def tearDownClass(cls):
        # This function is executed once after all the tests
        print("Ending Test Class")
        if(os.path.exists(cls.file_name)):
            os.remove(cls.file_name)


if __name__ == '__main__':
    unittest.main()
