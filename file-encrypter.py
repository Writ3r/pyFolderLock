#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
REQUIRES:
- pip install pyAesCrypt
- pip install cryptography
- pip install joblib
- pip install psutil
'''
import time
import os
import uuid
import base64
import joblib as joblib
import threading
import pyAesCrypt
import multiprocessing
import psutil

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# ================================================================
#
# Module scope variables.
#
# ================================================================
VERSION = '1.0.0'
#FILE_LOC = 'E:/testtttt/testFolder'
FILE_LOC = 'C:/temp/testFolder'
PASSWORD = 'TEST123'

# ================================================================
#
# Core Encrypt/Decrypt functions.
#
# ================================================================

def _calc_buffer_from_filesize(filename, buffer_size):
    filesize_bytes = os.path.getsize(filename)
    if filesize_bytes < buffer_size:
        buffer_size = filesize_bytes + (16 - (filesize_bytes % 16))
    return buffer_size

def encrypt_file(filename, tmpFilename, password, buffer_size):
    """
    Encrypts files via a stream using pyAesCrypt
    """
    buffer_size = _calc_buffer_from_filesize(filename,  buffer_size)
    pyAesCrypt.encryptFile(filename, tmpFilename, password, buffer_size)
    os.replace(tmpFilename, filename)

def decrypt_file(filename, tmpFilename, password, buffer_size):
    """
    Decrypts files via a stream using pyAesCrypt
    """
    buffer_size = _calc_buffer_from_filesize(filename,  buffer_size)
    pyAesCrypt.decryptFile(filename, tmpFilename, password, buffer_size)
    os.replace(tmpFilename, filename)

def encrypt_bytes(key, source, encode=True):
    """
    Encrypts bytes (for things like filenames)
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
    Decrypts bytes (for things like filenames)
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

def _get_filename(filepath):
    return str(Path(filepath).name)

def _get_parent(filepath):
    return str(Path(filepath).parent)

def _get_files_in_dir(potential_dir):
    fileList = []
    if os.path.isdir(potential_dir):
        fileList = os.listdir(potential_dir)
    return fileList

class _FileCreation:
    """
    Keeps track of filenames to keep duplicates from
    occuring. Exceedingly unlikely, but possible.
    """
    def __init__(self):
        self._fileNames = set()
        self._lock = threading.Lock()

    def get_filename(self):
        with self._lock:
            uuid_filename = str(uuid.uuid4())
            while uuid_filename in self._fileNames:
                uuid_filename = str(uuid.uuid4())
            self._fileNames.add(uuid_filename)
            return uuid_filename

class _DataStore:
    """
    Stores data about the encryption inside a metadata file
    """
    UUID_TO_FILENAME_KEY = "UUID_TO_FILENAME"

    def __init__(self, filepath):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._store = self._load_store()
        
    def get_data(self, key):
        with self._lock:
            if key in self._store:
                return self._store[key]

    def store_data(self, key, data):
        with self._lock:
            self._store[key] = data
    
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

# Runner
#=================================================================

class _RecursiveFileEncryptor:
    """
    Main class to contain all necessary objects/functions
    folder_location - location to encrypt/decrypt all files inside
    password - used for the encryption process
    max_threads - number of threads to use. (generally just enough to max disk usage)
                  note: this can significantly slow down computer operations, so reduce threads if needed
    file_buffer_size - number of bytes to use (needs to be multiple of 16).
                  note: higher number here == more memory usage, but faster processing
    """
    METADATA_FILE = '.encrypted_file_map'
    
    def __init__(self, folder_location, password, max_threads=multiprocessing.cpu_count(), file_buffer_size=None):
        self.folder_location = str(Path(folder_location))
        self.password = password
        self.file_buffer_size = file_buffer_size if file_buffer_size else self._calc_default_buffer(max_threads)
        self.metadata_file_location = os.path.join(self.folder_location, _RecursiveFileEncryptor.METADATA_FILE)
        self.encrypt_files = not(os.path.exists(self.metadata_file_location))
        self.thread_executor = ThreadPoolExecutor(max_workers=max_threads)
        self.fileCreation = _FileCreation()
        self.datastore = _DataStore(self.metadata_file_location)
        self.uuid_to_filename_dict = self._get_uuid_to_filename_dict(self.folder_location)

    # Managing functions
    #=================================================================

    def run(self):
        if os.path.isdir(self.folder_location):
            self._process_folder()
    
    def _process_folder(self):
        self._walk_encrypt_files(self.folder_location)
        self._walk_encrypt_names(self.folder_location)
        self._save_uuid_to_filename_dict(self.folder_location)
        self.datastore.save_store(not(self.encrypt_files))
    
    # Recursively walk directories
    #=================================================================

    def _walk_encrypt_files(self, file_input):
        futures = []
        for root, subdirs, subfiles in os.walk(file_input):
            for subfile in subfiles:
                if subfile != _RecursiveFileEncryptor.METADATA_FILE:
                    futures.append(self.thread_executor.submit(self._process_file, os.path.join(root, subfile)))
        wait(futures)
    
    def _walk_encrypt_names(self, filepath):
        for file_input in _get_files_in_dir(filepath):
            sub_filepath = os.path.join(filepath, file_input)
            self._walk_encrypt_names(sub_filepath)
            if _get_filename(sub_filepath) != _RecursiveFileEncryptor.METADATA_FILE:
                self._process_file_name(sub_filepath)
    
    # Encrypt/Decrypt files and filenames
    #=================================================================

    def _process_file(self, file_input):
        tmpFilename = os.path.join(_get_parent(file_input), self.fileCreation.get_filename()) + '.tmp'
        if self.encrypt_files:
            print('Encrypting: ' + file_input)
            encrypt_file(file_input, tmpFilename, self.password, self.file_buffer_size)
        else:
            print('Decrypting: ' + file_input)
            decrypt_file(file_input, tmpFilename, self.password, self.file_buffer_size)  

    def _process_file_name(self, file_input):
        if self.encrypt_files:
            filename = _get_filename(file_input)
            uuid_filename = self.fileCreation.get_filename()
            self.uuid_to_filename_dict[uuid_filename] = encrypt_bytes(str.encode(self.password), str.encode(filename), False)
            os.rename(file_input, os.path.join(_get_parent(file_input), uuid_filename))
        else:
            uuidName = _get_filename(file_input)
            if uuidName in self.uuid_to_filename_dict:
                uuid_filename = self.uuid_to_filename_dict[uuidName]
                real_filename = decrypt_bytes(str.encode(self.password), uuid_filename, False).decode()
                os.rename(file_input, os.path.join(_get_parent(file_input), real_filename))
    
    # File metadata saving
    #=================================================================

    def _get_uuid_to_filename_dict(self, filepath):
        if self.encrypt_files:
            return {}
        else:
            return self.datastore.get_data(_DataStore.UUID_TO_FILENAME_KEY)

    def _save_uuid_to_filename_dict(self, filepath):
        if self.encrypt_files:
            self.datastore.store_data(_DataStore.UUID_TO_FILENAME_KEY, self.uuid_to_filename_dict)
    
    # Utilities
    #=================================================================

    def _calc_default_buffer(threadCount, memoryMultiplier = 0.75):
        memory_bytes_per_thread = (psutil.virtual_memory().available * memoryMultiplier) // threadCount
        return int(memory_bytes_per_thread - (memory_bytes_per_thread % 16))

# ================================================================
#
# Main
#
# ================================================================

def main():
    '''
    main
    '''
    start = time.time()
    _RecursiveFileEncryptor(FILE_LOC, PASSWORD).run()
    end = time.time()
    print('Execution Time (seconds): ' + str(end - start))


if __name__ == '__main__':
    main()
