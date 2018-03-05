import os
import src.lib.cipher as lib_cipher
from src.lib.cipher import HIDDEN_FILE
import mock
import pytest
import re
from test.mock_connection import MockConnection
from src.lib.fs_parser import ParsedRet

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
    def test__copy_modified_time(self, cipher):
        add_files({'file1': None, 'file2': None})
        os.utime('file1', times=(0, 20))
        os.utime('file2', times=(0, 40))
        lib_cipher._copy_modified_time('file1', 'file2')
        assert(os.path.getmtime('file2') == 20)

    @mock.patch('src.lib.cipher.parse_fs')
    @mock.patch.object(lib_cipher.Cipher, 'encrypt_regular_filenames')
    @mock.patch.object(lib_cipher.Cipher, 'encrypt_hidden_filenames')
    def test_encrypt_files(self, en_hid, en_reg, parse_fs, cipher):
        ROOT1 = 'a'
        ROOT2 = 'b'
        REG1 = 'c'
        REG2 = 'd'
        HID1 = 'e'
        HID2 = 'f'
        RET1 = ParsedRet(ROOT1, regular_filenames=REG1, hidden_filenames=HID1)
        RET2 = ParsedRet(ROOT2, regular_filenames=REG2, hidden_filenames=HID2)
        parse_fs.return_value = iter([RET1, RET2])
        cipher.encrypt_file('arg')
        assert(parse_fs.call_count == 1)
        assert(en_reg.call_count == 2)
        assert(en_hid.call_count == 2)
        assert(en_reg.call_args_list[0][0] == (ROOT1, REG1))
        assert(en_reg.call_args_list[1][0] == (ROOT2, REG2))
        assert(en_hid.call_args_list[0][0] == (ROOT1, HID1))
        assert(en_hid.call_args_list[1][0] == (ROOT2, HID2))

    @mock.patch.object(lib_cipher, '_copy_modified_time')
    def test_encrypt_regular_folder(self, copy_modified_time, cipher):
        data = b'1234'
        data2 = b'4567'
        file_structure = {
            'folder1': {
                'file1': data,
                'file2': data2
            }
        }
        add_files(file_structure)
        cipher.encrypt_regular_filenames('folder1', ['file1', 'file2'])
        assert(os.listdir('folder1') == ['file1.enc', 'file2.enc'])
        assert(cipher.aes_layer.do_encode.call_count == 2)
        assert(cipher.aes_layer.do_encode.call_args_list[0][1] == {'data': data})
        assert(cipher.aes_layer.do_encode.call_args_list[1][1] == {'data': data2})
        assert(copy_modified_time.call_count == 2)

    @mock.patch('src.lib.cipher.logger.info')
    @mock.patch.object(lib_cipher, '_copy_modified_time')
    def test_encrypt_regular_file_dont_override(self, copy_modified_time, logging_info, cipher):
        logging_info.return_value = None
        data = b'1234'
        data2 = b'4567'
        file_structure = {
            'folder1': {
                'file1': data,
                'file1.enc': data2
            }
        }
        add_files(file_structure)
        cipher.encrypt_regular_filenames('folder1', ['file1'])
        assert(len(os.listdir('folder1')) == 2)
        assert('refusing' in logging_info.call_args[0][0])

    def test_encrypted_hidden_file(self, cipher):
        data = b'1234'
        folder_name = '.hidden'
        file_structure = {
            folder_name: {
                'file1-h': data,
            }
        }
        add_files(file_structure)
        cipher.encrypt_hidden_filenames(folder_name, ['file1-h'])
        print(os.listdir(folder_name))
        assert(len(os.listdir(folder_name)) == 1)
        assert(os.listdir(folder_name) == ['.hidden'])
