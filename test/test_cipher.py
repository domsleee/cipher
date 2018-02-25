import os
import src.lib.cipher as lib_cipher
from src.lib.cipher import HIDDEN_FILE
import mock
import pytest
import re
from test.mock_connection import MockConnection

AES_FOLDER = 'aes_folder'

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

@pytest.fixture()
def cipher(request, mocker):
    lib_cipher.AesLayer = mock.MagicMock(return_value=MockConnection())
    lib_cipher.HeaderLayer = mock.MagicMock(return_value=MockConnection())
    cipher = lib_cipher.Cipher(AES_FOLDER)
    conns = ['aes_layer', 'header_layer']
    methods = ['do_encode', 'do_decode', 'attach']
    for conn in conns:
        for method in methods:
            mocker.spy(getattr(cipher, conn), method)
    return cipher


@pytest.mark.usefixtures('fs')
class TestCipher(object):
    def test_basic_encrypt_file(self, cipher):
        data = b'1234'
        file_structure = {
            'folder1': {
                'file1': data
            }
        }
        add_files(file_structure)
        cipher.encrypt_file(os.path.join('folder1', 'file1'))

        expected_structure = {
            'file1.enc': None
        }
        assert(os.listdir('folder1') == ['file1.enc'])
        assert(cipher.aes_layer.do_encode.call_count == 1)
        assert(cipher.aes_layer.do_encode.call_args[0] == (data,))

    def test_basic_encrypt_folder(self, cipher):
        data = b'1234'
        data2 = b'4567'
        file_structure = {
            'folder1': {
                'file1': data,
                'file2': data2
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        expected_structure = {
            'file1.enc': None,
            'file2.enc': None
        }
        assert(os.listdir('folder1') == ['file1.enc', 'file2.enc'])
        assert(cipher.aes_layer.do_encode.call_count == 2)
        assert(cipher.aes_layer.do_encode.call_args_list[0][0] == (data,))
        assert(cipher.aes_layer.do_encode.call_args_list[1][0] == (data2,))

    def test_nested_file(self, cipher):
        file_structure = {
            'folder1': {
                'folder2': {
                    'file1': b'1234'
                }
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        expected_structure = {
            'file1.enc': None
        }
        folder_path = os.path.join('folder1', 'folder2')
        assert(os.listdir(folder_path) == ['file1.enc'])


    def test_already_encrypted(self, cipher):
        data = b'1234'
        file_structure = {
            'folder1': {
                'file1.enc': data
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        assert(os.listdir('folder1') == ['file1.enc'])
        with open(os.path.join('folder1', 'file1.enc'), 'rb') as file:
            assert(file.read() == data)

    @mock.patch('src.lib.cipher.logger.info')
    def test_dont_override(self, logging_info, cipher):
        logging_info.return_value = None
        file_structure = {
            'folder1': {
                'file1': b'1234',
                'file1.enc': b'1234'
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        assert(len(os.listdir('folder1')) == 2)
        assert('refusing' in logging_info.call_args[0][0])

    def test_modification_time_preserved(self, cipher):
        file_structure = {
            'folder1': {
                'file1': b'1234'
            }
        }
        add_files(file_structure)
        file_path = os.path.join('folder1', 'file1')

        with mock.patch('src.lib.cipher._copy_modified_time') as copy_modified_time:
            copy_modified_time.return_value = None
            cipher.encrypt_file('folder1')
            assert(copy_modified_time.call_count == 1)


    def test__copy_modified_time(self, cipher):
        add_files({'file1': None, 'file2': None})
        os.utime('file1', times=(0, 20))
        os.utime('file2', times=(0, 40))
        lib_cipher._copy_modified_time('file1', 'file2')
        assert(os.path.getmtime('file2') == 20)


    def test_hidden_file(self, cipher):
        file_structure = {
            'folder1': {
                'file1-h': b'1234'
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        assert(os.listdir('folder1') == [HIDDEN_FILE])
        file_path = os.path.join('folder1', HIDDEN_FILE)
        assert(os.path.isfile(file_path))

    def test_hidden_folder(self, cipher):
        file_structure = {
            'folder1': {
                'folder2-h': {
                    'file1-h': b'1234'
                }
            }
        }
        add_files(file_structure)
        cipher.encrypt_file('folder1')
        assert(os.listdir('folder1') == [HIDDEN_FILE])
        file_path = os.path.join('folder1', HIDDEN_FILE)
        assert(os.path.isfile(file_path))
