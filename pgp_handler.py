import pgpy



class pgpHandeler:
    def __init__(self):
        pass

    def encrypte(self, public_key, text):
        self.pubkey, _ = pgpy.PGPKey.from_blob(public_key)
        self.message_to_encrypt = pgpy.PGPMessage.new(text)
        self.encrypted_message = self.pubkey.encrypt(self.message_to_encrypt)
        return self.encrypted_message
        
    def decrypt(self, private_key, private_key_passphrase, text):
        self.privkey, _ = pgpy.PGPKey.from_blob(private_key)
        with self.privkey.unlock(private_key_passphrase) as ukey:
            self.message_to_decrypt = pgpy.PGPMessage.from_blob(text)
            self.decrypted_massage = ukey.decrypt(self.message_to_decrypt).message 

        return self.decrypted_massage