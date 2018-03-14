import os
import lib.cipher as lib_cipher
from lib.cipher import HIDDEN_FILE
import mock
import pytest
import re
from test.mock_connection import MockConnection
from test.mock_config import Config
from lib.fs_parser import ParsedRet

AES_FOLDER = 'aes_folder'
CONFIG = Config()
CONFIG.aes_folder = AES_FOLDER

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
    cipher = lib_cipher.Cipher(CONFIG)
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

    @mock.patch.object(lib_cipher, '_copy_modified_time')
    def test_cipher_and_move(self, copy_modified_time, cipher):
        data = b'1234'
        data2 = b'4567'
        file_structure = {
            'folder1': {
                'file1': data,
                'file2': data2
            }
        }
        add_files(file_structure)
        def f(filename):
            return os.path.join('folder1', filename)
        cipher.cipher_and_move(f('file1'), f('file1.enc'), cipher.aes_layer.do_encode)
        cipher.cipher_and_move(f('file2'), f('file2.enc'), cipher.aes_layer.do_encode)
        assert(sorted(os.listdir('folder1')) == sorted(['file1.enc', 'file2.enc']))
        assert(cipher.aes_layer.do_encode.call_count == 2)
        assert(cipher.aes_layer.do_encode.call_args_list[0][1] == {'data': data})
        assert(cipher.aes_layer.do_encode.call_args_list[1][1] == {'data': data2})
        assert(copy_modified_time.call_count == 2)

    @mock.patch('lib.cipher.logger.info')
    @mock.patch.object(lib_cipher, '_copy_modified_time')
    def test_cipher_and_move_dont_override(self, copy_modified_time, logging_info, cipher):
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
        filepath = os.path.join('folder1', 'file1')
        file_enc = os.path.join('folder1', 'file1.enc')
        cipher.cipher_and_move(filepath, file_enc, cipher.aes_layer.do_encode)
        assert(len(os.listdir('folder1')) == 2)
        assert('refusing' in logging_info.call_args[0][0])

    @mock.patch('lib.cipher.parse_fs')
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

    @mock.patch.object(lib_cipher.Cipher, 'cipher_and_move')
    def test_encrypt_regular_files(self, cipher_and_move, cipher):
        filepath = os.path.join('folder1', 'file1')
        file_enc = filepath + '.enc'
        cipher.encrypt_regular_filenames('folder1', ['file1'])
        assert(cipher_and_move.call_count == 1)
        assert(cipher_and_move.call_args_list[0][0] == (filepath, file_enc, cipher.aes_layer.do_encode))

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

    @mock.patch('lib.cipher.parse_fs')
    @mock.patch.object(lib_cipher.Cipher, 'decrypt_encrypted_filenames')
    @mock.patch.object(lib_cipher.Cipher, 'decrypt_encrypted_hidden_filenames')
    def test_decrypt_files(self, en_hid, en_files, parse_fs, cipher):
        ROOT1 = 'a'
        ROOT2 = 'b'
        EN1 = 'c'
        EN2 = 'd'
        ENHID1 = 'e'
        ENHID2 = 'f'
        RET1 = ParsedRet(ROOT1, encrypted_filenames=EN1, encrypted_hidden_filenames=ENHID1)
        RET2 = ParsedRet(ROOT2, encrypted_filenames=EN2, encrypted_hidden_filenames=ENHID2)
        parse_fs.return_value = iter([RET1, RET2])
        cipher.decrypt_file('arg')
        assert(parse_fs.call_count == 1)
        assert(en_files.call_count == 2)
        assert(en_files.call_args_list[0][0] == (ROOT1, EN1))
        assert(en_files.call_args_list[1][0] == (ROOT2, EN2))
        assert(en_hid.call_count == 2)
        assert(en_hid.call_args_list[0][0] == (ROOT1, ENHID1))
        assert(en_hid.call_args_list[1][0] == (ROOT2, ENHID2))

    @mock.patch.object(lib_cipher.Cipher, 'cipher_and_move')
    def test_decrypt_encrypted_filenames(self, cipher_and_move, cipher):
        filepath = os.path.join('folder1', 'file1')
        file_enc = filepath + '.enc'
        cipher.decrypt_encrypted_filenames('folder1', ['file1.enc'])
        assert(cipher_and_move.call_count == 1)
        assert(cipher_and_move.call_args_list[0][0] == (file_enc, filepath, cipher.aes_layer.do_decode))

    def test_decrypt_encrypted_hidden_filenames(self, cipher):
        with pytest.raises(NotImplementedError):
            cipher.decrypt_encrypted_hidden_filenames(None, None)

