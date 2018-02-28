import src.lib.fs_parser as fs_parser
import os
import pytest

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

@pytest.mark.usefixtures('fs')
class TestFsParser:
    def test_nested_folders(self):
        add_files({
            'folder1': {
                'folder2': {
                    'file1': b'1234'
                }
            }
        })
        i = 0
        for obj in fs_parser.parse_fs('folder1'):
            if i == 0:
                assert(obj.root == 'folder1')
            elif i == 1:
                assert(obj.root == os.path.join('folder1', 'folder2'))
                assert(obj.regular_filenames == ['file1'])
            i += 1

    def test_hidden_files(self):
        add_files({
            'folder1': {
                'yes-h.txt': None,
                'not-hidden.txt': None,
                'is_hidden-h': None,
                'hidden folder-h': {}
            }
        })
    
        i = 0
        for obj in fs_parser.parse_fs('folder1'):
            assert(i == 0)
            if i == 0:
                assert(obj.root == 'folder1')
                assert(obj.regular_filenames == ['not-hidden.txt'])
                assert(sorted(obj.hidden_filenames) == sorted(['yes-h.txt', 'is_hidden-h', 'hidden folder-h']))
            i += 1
