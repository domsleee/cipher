PRIVATE_KEY = 'abcd'
PUBLIC_KEY = 'defg'
AES_DIR = 'hijk'

class Config:
    def __init__(self):
        self.private_key = self.public_key = self.aes_dir = None

    def get_config(self, config_file=None):
        self.private_key = PRIVATE_KEY
        self.public_key = PUBLIC_KEY
        self.aes_dir = AES_DIR
