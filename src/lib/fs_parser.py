import re
import os
import ntpath

RE_HIDDEN_FILE = re.compile(r'-h($|\.)')
RE_ENCRYPTED_FILE = re.compile(r'\.enc$')
RE_ENCRYPTED_HIDDEN_FILE = re.compile(r'^.hidden\d*$')

def parse_fs(path):
    walk_override = None
    if os.path.isfile(path):
        walk_override = [(os.path.dirname(path), [], [ntpath.basename(path)])]

    use_walk = walk_override if walk_override else os.walk(path)
    for root, dirs, files in use_walk:
        hidden_filenames = []
        regular_filenames = []
        encrypted_filenames = []
        encrypted_hidden_filenames = []
        for file in dirs + files:
            filepath = os.path.join(root, file)
            if RE_ENCRYPTED_FILE.search(file):
                encrypted_filenames.append(file)
            elif RE_HIDDEN_FILE.search(file):
                hidden_filenames.append(file)
                if os.path.isdir(filepath):
                    dirs.remove(file)
            elif RE_ENCRYPTED_HIDDEN_FILE.search(file):
                encrypted_hidden_filenames.append(file)
            elif os.path.isfile(filepath):
                regular_filenames.append(file)

        yield {
            'root': root,
            'hidden_filenames': hidden_filenames,
            'regular_filenames': regular_filenames,
            'encrypted_filenames': encrypted_filenames,
            'encrypted_hidden_filenames': encrypted_hidden_filenames
        }
