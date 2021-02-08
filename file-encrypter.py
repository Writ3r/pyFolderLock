#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
REQUIRES:
- pip install pyAesCrypt   -stream file encryption
- pip install cryptography -byte encryption
- pip install joblib       -storing python objects
- pip install psutil       -getting system RAM information
'''
import time
import os
import base64
import joblib
import threading
import pyAesCrypt
import multiprocessing
import psutil
import logging
import argparse

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Event, Thread
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# ================================================================
#
# Module scope variables.
#
# ================================================================

VERSION = '1.0.0'
METHOD_BYTE_ENCRYPTION = 'BYTE_ENCRYPTION'
METHOD_STREAM_ENCRYPTION = 'STREAM_ENCRYPTION'
ENCRYPTED_EXT = '.locked'
EXT_PATH = '\\\\?\\' if os.name == 'nt' else ''

# ================================================================
#
# Core Encrypt/Decrypt functions.
#
# ================================================================

def _determine_encrypt_method(filename, buffer_size):
    filesize_bytes = os.path.getsize(filename)
    if filesize_bytes < buffer_size:
        return METHOD_BYTE_ENCRYPTION 
    return METHOD_STREAM_ENCRYPTION

def encrypt_file(filename, tmpFilename, password, buffer_size):
    """
    Encrypts files via a stream or via content based on size
    """
    encryptMethod = _determine_encrypt_method(filename, buffer_size)
    if encryptMethod == METHOD_STREAM_ENCRYPTION:
        pyAesCrypt.encryptFile(filename, tmpFilename, password, buffer_size)
        os.replace(tmpFilename, filename)
    else:
        output = encrypt_bytes(str.encode(password), _read_file(filename), encode=False)
        _write_file(filename, output)
    return encryptMethod

def decrypt_file(filename, tmpFilename, password, buffer_size, encryption_type):
    """
    Decrypts files via a stream or via content based on previous type
    """
    if encryption_type == METHOD_STREAM_ENCRYPTION:
        pyAesCrypt.decryptFile(filename, tmpFilename, password, buffer_size)
        os.replace(tmpFilename, filename)
    else:
        output = decrypt_bytes(str.encode(password), _read_file(filename), decode=False)
        _write_file(filename, output)

def encrypt_bytes(key, source, encode=True):
    """
    Encrypts bytes (used for things like strings/small files)
    https://stackoverflow.com/a/44212550/11381698
    """
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt_bytes(key, source, decode=True):
    """
    Decrypts bytes (used for things like strings/small files)
    https://stackoverflow.com/a/44212550/11381698
    """
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


# ================================================================
#
# Program specific parts.
#
# ================================================================

# Utilities
#=================================================================

#Functions
#=============

def _read_file(path, mode='rb'):
    with open(path, mode) as ifp:
        return ifp.read()

def _write_file(path, content):
    with open(path, 'wb') as ofp:
        ofp.write(content)

def _get_filename(filepath):
    return str(Path(filepath).name)

def _get_parent(filepath):
    return str(Path(filepath).parent)

def _get_num_files_in_dir(filepath):
    numFiles = 0
    numDirs = 0
    for root, subdirs, subfiles in os.walk(filepath):
        for subfile in subfiles:
            numFiles = numFiles + 1
        for subdir in subdirs:
            numDirs = numDirs + 1
    return numFiles, numDirs

#Classes
#=============

class _InvalidPasswordError(Exception):
    """Raised when password is invalid"""
    pass

class _RepeatedTimer:

    """
    Repeat `function` every `interval` seconds.
    https://stackoverflow.com/a/33054922/11381698
    """

    def __init__(self, interval, function, *args, **kwargs):
        self.interval = interval
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.start = time.time()
        self.event = Event()
        self.thread = Thread(target=self._target)
        self.thread.start()

    def _target(self):
        while not self.event.wait(self._time):
            self.function(*self.args, **self.kwargs)

    @property
    def _time(self):
        return self.interval - ((time.time() - self.start) % self.interval)

    def stop(self):
        self.event.set()
        self.thread.join()

class _FileCreation:
    """
    Keeps track of filenames to keep duplicates from occuring. 
    """
    def __init__(self):
        self._count = 0
        self._lock = threading.Lock()

    def get_filename(self):
        with self._lock:
            self._count = self._count + 1
            return str(self._count)

class _DataStore:
    """
    Stores data about the encryption inside a metadata file
    """
    UUID_TO_FILENAME_KEY = "UUID_TO_FILENAME"
    FILENAME_TO_ENCRYPTION_TYPE_KEY = "FILENAME_TO_ENCRYPTION_TYPE"
    PASSWORD_VERIFIER_KEY = "PASSWORD_VERIFIER"

    def __init__(self, filepath):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._store = self._load_store()
    
    def save_value(self, key, value):
        with self._lock:
            self._store[key] = value
    
    def get_value(self, key):
        with self._lock:
            if key in self._store:
                return self._store[key]
    
    def build_store(self, key, empty_collection):
        with self._lock:
            if key in self._store:
                return self._store[key]
            else:
                self._store[key] = empty_collection
                return self._store[key]
    
    def save_store(self, delete = False):
        with self._lock:
            self._delete_store() if delete else self._write_store()

    def _load_store(self):
        if os.path.exists(self._filepath):
            return joblib.load(self._filepath)
        else:
            return {}
    
    def _delete_store(self):
        os.remove(self._filepath)

    def _write_store(self):
        joblib.dump(self._store, self._filepath)

class _Metrics:
    """
    Manages metric information for the encryption process
    """
    def __init__(self, folder):
        self._folder =  folder[len(EXT_PATH):] if folder.startswith(EXT_PATH) else folder
        self._startTime = None
        self._filesProcessed = 0
        self._fileNamesProcessed = 0
        self._totalFiles, self._totalDirs = _get_num_files_in_dir(folder)
        self._totalFilesAndDirs = self._totalFiles + self._totalDirs
        self._lock = threading.Lock()
        self._sched = None
    
    def start(self, method):
        self._startTime = time.time()
        self._sched = _RepeatedTimer(1, method)
    
    def stop(self):
        self._sched.stop()
    
    # Metric calcs
    #============================
    
    def process_filename(self, filename):
        with self._lock:
            self._fileNamesProcessed = self._fileNamesProcessed + 1
        logging.debug('Processed filename: ' + filename)
    
    def process_file(self, filename):
        with self._lock:
            self._filesProcessed = self._filesProcessed + 1
        logging.debug('Processed file: ' + filename)
    
    def check_state(self, metric, metricName):
        totalFiles = self._totalFiles if metricName == 'FILES_PROCESSED' else self._totalFilesAndDirs
        return  {
                    'FOLDER' : self._folder,
                    'TOTAL_TIME_RUNNING (seconds)' : str(int(time.time() - self._startTime)),
                    metricName : metric,
                    'TOTAL_FILES' : totalFiles,
                    'PERCENT_COMPLETE' : int((metric / totalFiles) * 100) if totalFiles > 0 else 0
                }

    def print_state_files(self):
        logging.info(str(self.check_state(self._filesProcessed, 'FILES_PROCESSED')))
    
    def print_state_filenames(self):
        logging.info(str(self.check_state(self._fileNamesProcessed, 'FILENAMES_PROCESSED')))
    
# Runner
#=================================================================

class RecursiveFileEncryptor:
    """
    Main class to contain all necessary objects/functions
    folder_location - location to encrypt/decrypt all files inside
    password - used for the encryption process
    max_threads - number of threads to use.
    file_buffer_size - number of bytes to use (needs to be multiple of 16).
                  note: higher number here == more memory usage, but faster processing
                  note: passing in less than 1 calculates a default value.
    """
    METADATA_FILE = '.encrypted_file_map'
    
    def __init__(self, folder_location, password, verifyPassword, max_threads=multiprocessing.cpu_count(), file_buffer_size=0):
        self.verifyPassword = verifyPassword
        self.folder_location = EXT_PATH + str(Path(str(folder_location)))
        self.password = str(password)
        self.file_buffer_size = int(file_buffer_size) if int(file_buffer_size) > 0 else self._calc_default_buffer(int(max_threads))
        self.metadata_file_location = os.path.join(self.folder_location, RecursiveFileEncryptor.METADATA_FILE)
        self.encrypt_files = not(os.path.exists(self.metadata_file_location))
        self.thread_executor = ThreadPoolExecutor(max_workers=int(max_threads))
        self.fileCreation = _FileCreation()
        self.datastore = _DataStore(self.metadata_file_location)
        self._metrics = _Metrics(self.folder_location)
        self.uuid_to_filename_dict = self.datastore.build_store(_DataStore.UUID_TO_FILENAME_KEY, {})
        self.filename_to_encryptionType_dict = self.datastore.build_store(_DataStore.FILENAME_TO_ENCRYPTION_TYPE_KEY, {})

    # Managing functions
    #=================================================================

    def run(self):
        if os.path.isdir(self.folder_location):
            self._process_folder()
    
    def _process_folder(self):
        """
        encrypt/decrypt the filenames/dirs and files themselves
        filenames must go first, so the FILENAME_TO_ENCRYPTION_TYPE map can be safe.
        """
        if self.verifyPassword:
            self._verify_password(self.password)

        if self.encrypt_files:
            self._handle_encrypt_filenames()
            self._handle_encrypt_files()
        else:
            self._handle_encrypt_files()
            self._handle_encrypt_filenames()

        self.datastore.save_store(not(self.encrypt_files))
    
    def _handle_encrypt_files(self):
        self._metrics.start(self._metrics.print_state_files)
        self._walk_encrypt_files(self.folder_location)
        self._metrics.stop()
    
    def _handle_encrypt_filenames(self):
        self._metrics.start(self._metrics.print_state_filenames)
        self._walk_encrypt_names(self.folder_location)
        self._metrics.stop()
    
    # Recursively walk directories
    #=================================================================

    def _walk_encrypt_files(self, file_input):
        futures = []
        for root, subdirs, subfiles in os.walk(file_input):
            for subfile in subfiles:
                if subfile != RecursiveFileEncryptor.METADATA_FILE:
                    futures.append(self.thread_executor.submit(self._process_file, os.path.join(root, subfile)))
        wait(futures)
    
    def _walk_encrypt_names(self, filepath):
        if os.path.isdir(filepath):
            for file_input in os.listdir(filepath):
                self._walk_encrypt_names(os.path.join(filepath, file_input))
        if _get_filename(filepath) != RecursiveFileEncryptor.METADATA_FILE and filepath != self.folder_location:
            self._process_file_name(filepath)
    
    # Encrypt/Decrypt files and filenames
    #=================================================================

    def _process_file(self, file_input):
        tmpFilename = os.path.join(_get_parent(file_input), self.fileCreation.get_filename()) + '.tmp'
        if self.encrypt_files:
            file_input_enc = file_input + ENCRYPTED_EXT
            os.rename(file_input, file_input_enc)
            self.filename_to_encryptionType_dict[file_input_enc] = encrypt_file(file_input_enc, tmpFilename, self.password, self.file_buffer_size)
        else:
            if file_input[-len(ENCRYPTED_EXT):] == ENCRYPTED_EXT:
                decrypt_file(file_input, tmpFilename, self.password, self.file_buffer_size, self.filename_to_encryptionType_dict[file_input]) 
                os.rename(file_input, file_input[:-len(ENCRYPTED_EXT)])
        self._metrics.process_file(file_input) 

    def _process_file_name(self, file_input):
        input_name = _get_filename(file_input)
        output_file_name = None
        if self.encrypt_files:
            output_file_name = self.fileCreation.get_filename()
            self.uuid_to_filename_dict[output_file_name] = encrypt_bytes(str.encode(self.password), str.encode(input_name), False)
        else:
            if input_name in self.uuid_to_filename_dict:
                uuid_filename = self.uuid_to_filename_dict[input_name]
                output_file_name = decrypt_bytes(str.encode(self.password), uuid_filename, False).decode()
        if output_file_name:
            file_output = os.path.join(_get_parent(file_input), output_file_name)
            os.rename(file_input, file_output)
            self._metrics.process_filename(file_output)
    
    # Utilities
    #=================================================================

    def _calc_default_buffer(self, threadCount, memoryMultiplier = 0.75):
        memory_bytes_per_thread = (psutil.virtual_memory().available * memoryMultiplier) // threadCount
        return int(memory_bytes_per_thread - (memory_bytes_per_thread % 16))
    
    def _verify_password(self, password):
        if self.encrypt_files:
            encryptedPassword = encrypt_bytes(str.encode(self.password), str.encode(_DataStore.PASSWORD_VERIFIER_KEY), False)
            self.datastore.save_value(_DataStore.PASSWORD_VERIFIER_KEY, encryptedPassword)
        else:
            encryptedPassword = self.datastore.get_value(_DataStore.PASSWORD_VERIFIER_KEY)
            if encryptedPassword:
                decryptedPassword = decrypt_bytes(str.encode(self.password), encryptedPassword, False).decode()
                if decryptedPassword == _DataStore.PASSWORD_VERIFIER_KEY:
                    return None
            raise _InvalidPasswordError
# ================================================================
#
# Main
#
# ================================================================

def main():
    '''
    Takes input for password + folder(s)
    Ex.  file-encrypter.py TEST123 E:/testtttt/testFolder "E:/testtttt/Everything Needed"
    Ex.  file-encrypter.py TEST123 "E:/testtttt/Everything Needed"
    Ex.  file-encrypter.py --pwdfile E:/testtttt/pwd.txt E:/testtttt/testFolder
    '''
    parser = argparse.ArgumentParser(description='Encrypts folder contents with provided password.')

    #optional arg to specify password field is a file which has password inside it
    parser.add_argument("--pwdfile", action='store_true', 
                        help="uses password stored in file (to avoid cmdline history)")

    #optional arg to enable password verification
    parser.add_argument("--verify", action='store_true', 
                        help="""Checks if password is correct before decrypting. Must have been run on initial encrypt.
                              (keep in mind, this does provide an avenue for brute forcing)""")
    
    #arg for password
    def _check_password(password):
        if len(password) <= 0:
            raise argparse.ArgumentTypeError("%s is an invalid password" % password)
        return password

    parser.add_argument("password", type=_check_password, 
                        help="password which will be used for the encryption/decryption")
    
    #arg for folder(s)
    def _check_folder(folder):
        if not(os.path.isdir(folder)):
            raise argparse.ArgumentTypeError("%s is an invalid folder" % folder)
        return folder

    parser.add_argument("folders", type=_check_folder, nargs="*",
                        help="folder whose contents will be encrypted/decrypted")

    args = parser.parse_args()

    #handle specifying password is a file
    if args.pwdfile:
        if os.path.exists(args.password):
            args.password = _read_file(args.password,"r+")
        else:
            raise argparse.ArgumentTypeError("%s does not exist" % args.password)
    
    #logging setup
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
    logging.getLogger('apscheduler').setLevel(logging.WARNING)

    #run encrypt/decrypt on all folders
    for folder in args.folders:
        try:
            RecursiveFileEncryptor(os.path.abspath(folder), args.password, args.verify).run()
        except _InvalidPasswordError:
            print("The password you entered is invalid for: " + folder)


if __name__ == '__main__':
    main()
