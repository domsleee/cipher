"""Groups files/folders from filesystem.

parse_fs is a generator that interprets the file system
and returns groups of files by folder

"""
import re
import os
import ntpath

RE_HIDDEN_FILE = re.compile(r'-h($|\.)')
RE_ENCRYPTED_FILE = re.compile(r'\.enc$')
RE_ENCRYPTED_HIDDEN_FILE = re.compile(r'^.hidden\d*$')

class ParsedRet:
    def __init__(self, root, regular_filenames=None, hidden_filenames=None,
                 encrypted_filenames=None, encrypted_hidden_filenames=None):
        self.root = root
        self.hidden_filenames = hidden_filenames
        self.regular_filenames = regular_filenames
        self.encrypted_filenames = encrypted_filenames
        self.encrypted_hidden_filenames = encrypted_hidden_filenames

def parse_fs(path):
    walk_override = None
    if os.path.isfile(path):
        walk_override = [(os.path.dirname(path), [], [ntpath.basename(path)])]

    use_walk = walk_override if walk_override else os.walk(path)
    for root, dirs, files in use_walk:
        ret = ParsedRet(root, [], [], [], [])
        for file in dirs + files:
            filepath = os.path.join(root, file)
            if RE_ENCRYPTED_FILE.search(file):
                ret.encrypted_filenames.append(file)
            elif RE_HIDDEN_FILE.search(file):
                ret.hidden_filenames.append(file)
                if os.path.isdir(filepath):
                    dirs.remove(file)
            elif RE_ENCRYPTED_HIDDEN_FILE.search(file):
                ret.encrypted_hidden_filenames.append(file)
            elif os.path.isfile(filepath):
                ret.regular_filenames.append(file)
        yield ret
