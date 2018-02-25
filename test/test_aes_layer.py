from src.lib.aes_layer import AesLayer
import src.lib.aes_layer
from test import mock_rsa
from test import mock_aes
import pytest
import os
import re
import mock

AES_FOLDER = 'aes_folder'
AES_DIR = AES_FOLDER
AES_FILENAME = 'a'*10
AES_FILE = os.path.join(AES_FOLDER, AES_FILENAME)

src.lib.aes_layer.lib_rsa = mock_rsa
src.lib.aes_layer.lib_aes = mock_aes

# TODO
# - Consider property testing for time preserved

@pytest.fixture()
def setup_folders(request):
    file_structure = {
        AES_FOLDER: {
            AES_FILENAME: None
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
class TestAesLayer:
    def setup(self):
        self.aes_filename = AES_FILENAME
        self.aes_layer = AesLayer(AES_DIR)
        self.mock_aes = mock_aes.Aes(None)

    def test_constructor_uses_aes(self):
        assert(len(os.listdir(AES_FOLDER)) == 1)

    def test_constructor_creates_aes_if_none(self):
        file_structure = {
            'folder1': {}
        }
        add_files(file_structure)
        AesLayer('folder1')
        assert(len(os.listdir('folder1')) == 1)

    def test_constructor_creates_aes_if_cant_decrypt(self):
        file_structure = {
            'folder1': {AES_FILENAME: None}
        }
        add_files(file_structure)
        with mock.patch('src.lib.aes_layer.lib_rsa.Rsa.can_decrypt') as can_decrypt:
            can_decrypt.return_value = False
            AesLayer('folder1')
            assert(len(os.listdir('folder1')) == 2)

    def test_encode(self):
        data = b'1234'
        res = self.aes_layer.do_encode(data)
        assert(len(res) == 2)
        assert(res['data'] == self.mock_aes.encrypt(data))
        assert(res['aes_filename'] == AES_FILENAME)

    def test_decode(self):
        data = b'12345'
        res = self.aes_layer.do_decode({'data': data, 'aes_filename': AES_FILENAME})
        assert(res == self.mock_aes.decrypt(data))

