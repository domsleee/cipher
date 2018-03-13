import lib.config as lib_config
CONFIG_FILEPATH = 'cipher.cfg'

class TestConfig:
    def setup(self):
        self.cfg = lib_config.Config()

    def test_empty_config(self, fs):
        with open(CONFIG_FILEPATH, 'w') as file:
            file.write('')
        self.cfg.get_config(CONFIG_FILEPATH)
        assert(self.cfg.private_key == None)
        assert(self.cfg.public_key == None)
        assert(self.cfg.aes_dir == None)

    def test_normal_config(self, fs):
        private_key = 'abcd'
        public_key = 'defg'
        aes_dir = 'hijk'
        cfg = (
        'private_key = ' + private_key + '\n'
        'public_key = ' + public_key + '\n'
        'aes_dir = ' + aes_dir + '\n'
        )
        with open(CONFIG_FILEPATH, 'w') as file:
            file.write(cfg)
        self.cfg.get_config(CONFIG_FILEPATH)
        assert(self.cfg.private_key == private_key)
        assert(self.cfg.public_key == public_key)
        assert(self.cfg.aes_dir == aes_dir)
