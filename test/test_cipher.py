import os
import src.lib.cipher as lib_cipher
import test.mock_aes as mock_aes
import test.mock_rsa as mock_rsa
import mock
import pytest
import re

AES_FOLDER = 'aes_folder'
AES_FILENAME = 'a'*10
AES_FILE = os.path.join(AES_FOLDER, AES_FILENAME)
RSA_FOLDER = '.enc'
RSA_PUB_FILENAME = 'rsa.pub'
RSA_PRIV_FILENAME = 'rsa.key'
RSA_PUB_FILE = os.path.join(RSA_FOLDER, RSA_PUB_FILENAME)
RSA_PRIV_FILE = os.path.join(RSA_FOLDER, RSA_PRIV_FILENAME)

lib_cipher.lib_rsa = mock_rsa
lib_cipher.lib_aes = mock_aes

# TODO
# - Consider property testing for time preserved

@pytest.fixture()
def setup_folders(request):
    rsa = mock_rsa.Rsa()
    file_structure = {
        AES_FOLDER: {
            AES_FILENAME: rsa.encrypt(mock_aes.AES_SECRET)
        },
        RSA_FOLDER: {
            RSA_PUB_FILENAME: None,
            RSA_PRIV_FILENAME: None
        }
    }
    add_files(file_structure)


def add_files(structure, path='.'):
    for key in structure:
        new_path = os.path.join(path, key)
        val = structure[key]
        if isinstance(val, dict):
            os.mkdir(new_path)
            add_files(val, path=new_path)
        else:
            data = val if val else b'.'
            with open(new_path, 'wb') as file:
                file.write(data)


@pytest.mark.usefixtures('fs', 'setup_folders')
class TestCipher(object):
    def test_constructor_uses_aes(self):
        cipher = lib_cipher.Cipher(AES_FOLDER, rsa_priv=RSA_PRIV_FILE, aes_filename=AES_FILENAME)
        assert(len(os.listdir(AES_FOLDER)) == 1)

        rsa = mock_rsa.Rsa()
        with open(os.path.join(AES_FOLDER, AES_FILENAME), 'rb') as file:
            assert(rsa.decrypt(file.read()) == mock_aes.AES_SECRET)

    def test_constructor_creates_aes(self):
        cipher = lib_cipher.Cipher(AES_FOLDER, rsa_pub=RSA_PUB_FILE)
        assert(len(os.listdir(AES_FOLDER)) == 2)
        aes_filename = None
        for filename in os.listdir(AES_FOLDER):
            if filename != AES_FILENAME:
                aes_filename = filename

        assert(len(aes_filename) == 10)
        assert(re.match(r'[a-z0-9]{10}', aes_filename))

        rsa = mock_rsa.Rsa()
        with open(os.path.join(AES_FOLDER, aes_filename), 'rb') as file:
            assert(rsa.decrypt(file.read()) == mock_aes.AES_SECRET)


    def test_basic_encrypt_file(self):
        file_structure = {
            'folder1': {
                'file1': b'1234'
            }
        }
        add_files(file_structure)

        cipher = lib_cipher.Cipher(AES_FOLDER, rsa_pub=RSA_PUB_FILE)
        cipher.encrypt_file('folder1')

        expected_structure = {
            'file1.enc': None
        }
        assert(os.listdir('folder1') == ['file1.enc'])
        with open(os.path.join('folder1', 'file1.enc'), 'rb') as file:
            assert(file.read() == b'4321')


    def test_already_encrypted(self):
        file_structure = {
            'folder1': {
                'file1.enc': b'1234'
            }
        }
        add_files(file_structure)

        cipher = lib_cipher.Cipher(AES_FOLDER, rsa_pub=RSA_PUB_FILE)
        cipher.encrypt_file('folder1')

        assert(os.listdir('folder1') == ['file1.enc'])
        with open(os.path.join('folder1', 'file1.enc'), 'rb') as file:
            assert(file.read() == b'1234')

    def test_modification_time_preserved(self):
        file_structure = {
            'folder1': {
                'file1': b'1234'
            }
        }
        add_files(file_structure)
        file_path = os.path.join('folder1', 'file1')
        modified_time = 50.5123
        os.utime(file_path, times=(50, modified_time))
        assert(os.path.getmtime(file_path) == modified_time)

        cipher = lib_cipher.Cipher(AES_FOLDER, rsa_pub=RSA_PUB_FILE)
        cipher.encrypt_file('folder1')
        assert(os.path.getmtime(file_path+'.enc') == modified_time)


