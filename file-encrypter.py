#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
REQUIRES:
- pip install pyAesCrypt
- pip install cryptography
'''
import time
import os
import uuid
import base64
import joblib as joblib
import threading
import pyAesCrypt
import multiprocessing

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait
from threading import Semaphore
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

# ================================================================
#
# Module scope variables.
#
# ================================================================

VERSION = '1.0.0'
FILE_LOC = 'C:/temp/testFolder'
PASSWORD = 'TEST123'
METADATA_FILE = '.encrypted_file_map'
ENCRYPT_BUTTER_SIZE = 64 * 1048576

# ================================================================
#
# Core Encrypt/Decrypt functions.
# https://stackoverflow.com/a/44212550/11381698
#
# ================================================================

class EncryptionUtils:

    def encrypt_file(self, filename, password):
        filename_encrypt = str(Path(filename).parent) + os.path.sep + fileCreation.get_filename()
        pyAesCrypt.encryptFile(filename, filename_encrypt, password, ENCRYPT_BUTTER_SIZE)
        os.replace(filename_encrypt, filename)

    def decrypt_file(self, filename, password):
        filename_decrypt = str(Path(filename).parent) + os.path.sep + fileCreation.get_filename()
        pyAesCrypt.decryptFile(filename, filename_decrypt, password, ENCRYPT_BUTTER_SIZE)
        os.replace(filename_decrypt, filename)

    def encrypt_string(self, key, source, encode=True):
        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = Random.new().read(AES.block_size)  # generate IV
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
        source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
        data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
        return base64.b64encode(data).decode("latin-1") if encode else data

    def decrypt_string(self, key, source, decode=True):
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
# Program specific functions.
#
# ================================================================

# Utilities
#=================================================================

class ThreadCounter:
    """
    Somewhat hacky class to keep a count of threads in/out of the pool at a time.
    As long as this class counts == or a bit higher than
    the number of threads actually in the pool, then it is working correctly.
    """
    def __init__(self, max_threads):
        self._value = 0
        self._max_threads = max_threads
        self._lock = threading.Lock()
        
    def increment(self):
        with self._lock:
            self._value += 1
    
    def decrement(self):
        with self._lock:
            self._value -= 1
    
    def is_under_max(self):
        with self._lock:
            return self._value < self._max_threads

class FileCreation:
    """
    Keeps track of filenames to keep duplicates from
    occuring. Exceedingly unlikely, but possible.
    """
    def __init__(self):
        self._fileNames = set()
        self._lock = threading.Lock()

    def get_filename(self):
        with lock:
            uuid_filename = str(uuid.uuid4())
            while uuid_filename in self._fileNames:
                uuid_filename = str(uuid.uuid4())
            self._fileNames.add(uuid_filename)
            return uuid_filename

# File metadata saving
#=================================================================

def get_uuid_to_filename_dict(filepath, encryptFiles):
    if encryptFiles is True:
        return {}
    else:
        load_filename = str(Path(filepath)) + os.path.sep + METADATA_FILE
        return joblib.load(load_filename)

def save_uuid_to_filename_dict(filepath, uuid_to_filename_dict, encryptFiles):
    save_filename = str(Path(filepath)) + os.path.sep + METADATA_FILE
    if encryptFiles is True:
        joblib.dump(uuid_to_filename_dict, save_filename)
    else:
        os.remove(save_filename)

# Encrypt/Decrypt data
#=================================================================

def process_file(file_input, password, encryptFiles):
    if encryptFiles:
        encryptionUtils.encrypt_file(file_input, password)
    else:
        encryptionUtils.decrypt_file(file_input, password)

def process_file_name(file_input, password, encryptFiles, uuid_to_entry_dict):
    password = str.encode(password)
    if encryptFiles:
        filename = Path(file_input).name
        uuid_filename = fileCreation.get_filename()
        uuid_to_entry_dict[uuid_filename] = encryptionUtils.encrypt_string(password, str.encode(filename), False)
        os.rename(file_input, str(Path(file_input).parent) + os.path.sep + uuid_filename)
    else:
        uuidName = Path(file_input).name
        if uuidName in uuid_to_entry_dict:
            uuid_filename = uuid_to_entry_dict[uuidName]
            real_filename = encryptionUtils.decrypt_string(password, uuid_filename, False).decode()
            os.rename(file_input, str(Path(file_input).parent) + os.path.sep + real_filename)

# Recursively walk directories
#=================================================================

def get_files_in_dir(potential_dir):
    fileList = []
    if os.path.isdir(potential_dir):
        fileList = os.listdir(potential_dir)
    return fileList

def process_dir_subfile(file_input, filepath, password, encryptFiles, uuid_to_filename_dict):
    full_filename = str(Path(filepath)) + os.path.sep + file_input
    recursive_process(full_filename, password, encryptFiles, uuid_to_filename_dict)
    if file_input != METADATA_FILE:
        if not(os.path.isdir(full_filename)): process_file(full_filename, password, encryptFiles)
        process_file_name(full_filename, password, encryptFiles, uuid_to_filename_dict)

def done_cbk(future):
    threadCounter.decrement()

def recursive_process(filepath, password, encryptFiles, uuid_to_filename_dict):
    futures = []
    for file_input in get_files_in_dir(filepath):
        if threadCounter.is_under_max():
            threadCounter.increment()
            future = executor.submit(process_dir_subfile, file_input, filepath, password, encryptFiles, uuid_to_filename_dict)
            future.add_done_callback(done_cbk)
            futures.append(future)
        else:
            process_dir_subfile(file_input, filepath, password, encryptFiles, uuid_to_filename_dict)
    wait(futures)

def process_input(filepath, password, encryptFiles):
    if os.path.isdir(filepath):
        uuid_to_filename_dict = get_uuid_to_filename_dict(filepath, encryptFiles)
        recursive_process(filepath, password, encryptFiles, uuid_to_filename_dict)
        save_uuid_to_filename_dict(filepath, uuid_to_filename_dict, encryptFiles)

# Run
#=================================================================

def run(filepath, password):
    encrypt = not(os.path.exists(str(Path(filepath)) + os.path.sep + METADATA_FILE))
    process_input(filepath, password, encrypt)

# ================================================================
#
# Main
#
# ================================================================

encryptionUtils = EncryptionUtils()
fileCreation = FileCreation()
MAX_THREADS = multiprocessing.cpu_count()
executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
threadCounter = ThreadCounter(MAX_THREADS)
lock = threading.Lock()

def main():
    '''
    main
    '''
    start = time.time()
    run(FILE_LOC, PASSWORD)
    end = time.time()
    print('Execution Time (seconds): ' + str(end - start))


if __name__ == '__main__':
    main()
