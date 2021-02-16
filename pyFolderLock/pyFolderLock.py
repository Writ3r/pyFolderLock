#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
MAX_PASS_LENGTH = 1024

# ================================================================
#
# Core Encrypt/Decrypt functions.
#
# ================================================================


def _determine_encrypt_method(filename, bufferSize):
    filesizeBytes = os.path.getsize(filename)
    if filesizeBytes < bufferSize:
        return METHOD_BYTE_ENCRYPTION
    return METHOD_STREAM_ENCRYPTION


def encrypt_file(filename, tmpFilename, password, bufferSize):
    """
    Encrypts files via a stream or via content based on size
    """
    encryptionType = _determine_encrypt_method(filename, bufferSize)
    if encryptionType == METHOD_STREAM_ENCRYPTION:
        pyAesCrypt.encryptFile(filename, tmpFilename, password, bufferSize)
        os.replace(tmpFilename, filename)
    else:
        output = encrypt_bytes(str.encode(password), _read_file(filename),
                               encode=False)
        _write_file(filename, output)
    return encryptionType


def decrypt_file(filename, tmpFilename, password, bufferSize, encryptionType):
    """
    Decrypts files via a stream or via content based on previous type
    """
    if encryptionType == METHOD_STREAM_ENCRYPTION:
        pyAesCrypt.decryptFile(filename, tmpFilename, password, bufferSize)
        os.replace(tmpFilename, filename)
    else:
        output = decrypt_bytes(str.encode(password),
                               _read_file(filename),
                               decode=False)
        _write_file(filename, output)


def encrypt_bytes(key, source, encode=True):
    """
    Encrypts bytes (used for things like strings/small files)
    https://stackoverflow.com/a/44212550/11381698
    """
    key = SHA256.new(key).digest()
    IV = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size
    source += bytes([padding]) * padding
    data = IV + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt_bytes(key, source, decode=True):
    """
    Decrypts bytes (used for things like strings/small files)
    https://stackoverflow.com/a/44212550/11381698
    """
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()
    IV = source[:AES.block_size]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])
    padding = data[-1]
    if data[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding...")
    return data[:-padding]


# ================================================================
#
# Program specific parts.
#
# ================================================================

# Utilities
# =================================================================

# Functions
# =============


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


def _get_curr_names(filepath):
    filenames = []
    dirnames = []
    for ternary in os.walk(filepath):
        for direc in ternary[1]:
            dirnames.append(direc)
        for filename in ternary[2]:
            filenames.append(filename)
    return dirnames, filenames


def _is_non_empty_file(fpath):
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0

# Classes
# =============


class InvalidPasswordError(Exception):
    """Raised when password is invalid"""
    pass


class InvalidArgumentError(Exception):
    """Raised when argument is invalid"""
    def __init__(self, arg, reason):
        self.arg = arg
        self.reason = reason
        self.msg = "Argument [{0}] is invalid because [{1}]".format(self.arg, self.reason)
        super().__init__(self.msg)


class _RepeatedTimer:
    """
    Repeat `function` every `interval` seconds.
    https://stackoverflow.com/a/33054922/11381698
    """
    def __init__(self, interval, function, *args, **kwargs):
        self._interval = interval
        self._function = function
        self._args = args
        self._kwargs = kwargs
        self._start = time.time()
        self._event = Event()
        self._thread = Thread(target=self._target)
        self._thread.start()

    def _target(self):
        while not self._event.wait(self._time):
            self._function(*self._args, **self._kwargs)

    @property
    def _time(self):
        return self._interval - ((time.time() - self._start) % self._interval)

    def stop(self):
        self._event.set()
        self._thread.join()


class _FileCreation:
    """
    Keeps track of filenames to keep duplicates from occuring.
    Uses a custom base of filename safe chars
    """
    def __init__(self, nameBlacklist):
        self._count = 0
        self._customBaseInp = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self._customBase = len(self._customBaseInp)
        self._lock = threading.Lock()
        self._nameBlacklist = nameBlacklist

    def _convert_to_base(self, num):
        if num < self._customBase:
            return self._customBaseInp[num]
        else:
            return (self._convert_to_base(num // self._customBase)
                    + self._customBaseInp[num % self._customBase])

    def get_filename(self):
        with self._lock:
            while True:
                self._count += 1
                result = self._convert_to_base(self._count)
                if (not(result in self._nameBlacklist)):
                    return result


class _DataStore:
    """
    Stores data about the encryption inside a metadata file
    """
    UUID_TO_FILENAME_KEY = "UUID_TO_FILENAME"
    FNAME_TO_ENC_TYPE_KEY = "FILENAME_TO_ENCRYPTION_TYPE"
    PASSWORD_VERIFIER_KEY = "PASSWORD_VERIFIER"

    KEY_TO_STORE = {UUID_TO_FILENAME_KEY: {},
                    FNAME_TO_ENC_TYPE_KEY: {},
                    PASSWORD_VERIFIER_KEY: PASSWORD_VERIFIER_KEY}

    def __init__(self, filepath):
        self._filepath = filepath
        self._lock = threading.Lock()
        self._store = self._load_store()
        for key in _DataStore.KEY_TO_STORE:
            self.build_store(key)

    def save_value(self, key, value):
        with self._lock:
            self._store[key] = value

    def get_value(self, key):
        with self._lock:
            if key in self._store:
                return self._store[key]

    def build_store(self, key):
        with self._lock:
            if key in self._store:
                return self._store[key]
            else:
                self._store[key] = _DataStore.KEY_TO_STORE[key]
                return self._store[key]

    def save_store(self, delete=False):
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
        joblib.dump(self._store, self._filepath, compress=9)


class _Metrics:
    """
    Manages metric information for the encryption process
    """
    def __init__(self, folder, enabled, numFiles, numFolders):
        self._enabled = enabled
        if self._enabled:
            self._folder = folder[len(EXT_PATH):]
            self._startTime = None
            self._filesProcessed = 0
            self._fileNamesProcessed = 0
            self._totalFiles = numFiles
            self._totalDirs = numFolders
            self._totalFilesAndDirs = numFiles + numFolders
            self._lock = threading.Lock()
            self._sched = None

    def start(self, method):
        if self._enabled:
            self._startTime = time.time()
            self._sched = _RepeatedTimer(1, method)

    def stop(self):
        if self._enabled:
            self._sched.stop()

    # Metric calcs
    # ============================

    def process_filename(self, filename):
        if self._enabled:
            with self._lock:
                self._fileNamesProcessed += 1
            logging.debug('Processed filename: ' + filename)

    def process_file(self, filename):
        if self._enabled:
            with self._lock:
                self._filesProcessed += 1
            logging.debug('Processed file: ' + filename)

    def check_state(self, metric, metricName):
        if self._enabled:
            totalFiles = self._totalFiles
            if metricName == 'FILENAMES_PROCESSED':
                totalFiles = self._totalFilesAndDirs
            timeRunning = str(int(time.time() - self._startTime))
            percentComplete = 0
            if totalFiles > 0:
                percentComplete = int((metric / totalFiles) * 100)

            return {
                        'FOLDER': self._folder,
                        'TIME_RUNNING (s)': timeRunning,
                        metricName: metric,
                        'TOTAL_FILES': totalFiles,
                        'PERCENT_COMPLETE': percentComplete
                    }

    def print_state_files(self):
        if self._enabled:
            logging.info(str(self.check_state(self._filesProcessed,
                                              'FILES_PROCESSED')))

    def print_state_filenames(self):
        if self._enabled:
            logging.info(str(self.check_state(self._fileNamesProcessed,
                                              'FILENAMES_PROCESSED')))


# Runner
# =================================================================


class MultiFolderEncryptor:
    """
    Encrypts/Decrypts contents of the passed in folder
        folders - list of folders. replaces 'folder' arg in FolderEncryptor
        - rest of args are derived from FolderEncryptor
    """
    def __init__(self,
                 folders,
                 password,
                 **kwargs):

        # list of encrypters to run
        self.folderEncryptors = []

        # handle case of single folder, no list
        if isinstance(folders, str):
            folders = [folders]

        # create folder encryptors for each folder
        for folder in folders:
            try:
                folderEncryptor = FolderEncryptor(folder, password, **kwargs)
                self.folderEncryptors.append(folderEncryptor)
            except InvalidPasswordError:
                logging.error("The password you entered is invalid for: " + folder)
            except InvalidArgumentError as e:
                logging.error(str(e.msg))

    # Managing functions
    # =================================================================

    def run(self):
        """ Executes the encrypt/decrypt processes on all folderEncryptors"""
        for folderEncryptor in self.folderEncryptors:
            try:
                folderEncryptor.run()
            except Exception:
                logging.error("Failed to execute encrypt/decrypt on folder: [{0}]"
                              .format(folderEncryptor.folderLocation))


class FolderEncryptor:
    """
    Encrypts/Decrypts contents of the passed in folder
        folder - location to encrypt/decrypt all files inside
        password - used for the encryption process
        opt: passwordFile - specifies if password arg is a file with pass inside
        opt: verifyPassword - checks if password is correct b4 decrypting
        opt: metricsEnabled - turms on/off metrics thread
        opt: maxThreads - number of threads to use.
        opt: memory - max memory to use. 0 or less calculates default.
        opt: memoryMultiplier - multiplier on the max memory
    """
    METADATA_FILE = '.encryption_context'
    TMP_FILE_EXT = '.tmp'

    def __init__(self,
                 folder,
                 password,
                 passwordFile=False,
                 verifyPassword=False,
                 metricsEnabled=True,
                 maxThreads=multiprocessing.cpu_count(),
                 memory=0,
                 memoryMultiplier=.75):

        # check arg validity
        self._check_args(folder,
                         password,
                         passwordFile,
                         verifyPassword,
                         metricsEnabled,
                         maxThreads,
                         memory,
                         memoryMultiplier)

        # build folder specific vars
        self.folderLocation = EXT_PATH + str(Path(os.path.abspath(folder)))
        dirnames, filenames = _get_curr_names(self.folderLocation)
        self._metadataFileLoc = os.path.join(self.folderLocation,
                                             FolderEncryptor.METADATA_FILE)
        self._encryptFiles = not(os.path.exists(self._metadataFileLoc))

        # dependent objects
        self._threadExec = ThreadPoolExecutor(max_workers=maxThreads)
        self._fileCreation = _FileCreation(set(dirnames + filenames))
        self._datasource = _DataStore(self._metadataFileLoc)
        self._metrics = _Metrics(self.folderLocation,
                                 metricsEnabled,
                                 len(filenames),
                                 len(dirnames))

        # handle password
        self._password = password if not(passwordFile) else _read_file(password, "r+")
        if verifyPassword:
            self._verify_password(self._password)

        # dependent vars
        self._uuidToFilenameDict = self._datasource.get_value(_DataStore.UUID_TO_FILENAME_KEY)
        self._fileToEncTypeDict = self._datasource.get_value(_DataStore.FNAME_TO_ENC_TYPE_KEY)
        self._fileBufferSize = self._calc_default_buffer(maxThreads,
                                                         memory,
                                                         memoryMultiplier=memoryMultiplier)

    # Managing functions
    # =================================================================

    def run(self):
        """ Executtes the encrypt/decrypt processes """
        if os.path.isdir(self.folderLocation):
            self._process_folder()

    def _process_folder(self):
        if self._encryptFiles:
            self._handle_encrypt_filenames()
            self._handle_encrypt_files()
        else:
            self._handle_encrypt_files()
            self._handle_encrypt_filenames()
        self._datasource.save_store(not(self._encryptFiles)
                                    or len(self._uuidToFilenameDict) == 0)

    def _handle_encrypt_files(self):
        self._metrics.start(self._metrics.print_state_files)
        self._walk_encrypt_files(self.folderLocation)
        self._metrics.stop()

    def _handle_encrypt_filenames(self):
        self._metrics.start(self._metrics.print_state_filenames)
        self._walk_encrypt_names(self.folderLocation)
        self._metrics.stop()

    # Recursively walk directories
    # =================================================================

    def _walk_encrypt_files(self, fileInput):
        futures = []
        for ternary in os.walk(fileInput):
            root = ternary[0]
            subfiles = ternary[2]
            for subfile in subfiles:
                if subfile != FolderEncryptor.METADATA_FILE:
                    futures.append(self._threadExec.submit(self._process_file,
                                                           os.path.join(root, subfile)))
        wait(futures)

    def _walk_encrypt_names(self, filepath):
        if os.path.isdir(filepath):
            for fileInput in os.listdir(filepath):
                self._walk_encrypt_names(os.path.join(filepath, fileInput))
        self._process_file_name(filepath)

    # Encrypt/Decrypt files
    # =================================================================

    def _process_file(self, fileInput):
        try:
            if _is_non_empty_file(fileInput) and os.access(fileInput, os.W_OK):
                tmpFilename = os.path.join(_get_parent(fileInput),
                                           self._fileCreation.get_filename()) + '.tmp'
                if self._encryptFiles:
                    self._process_encrypt_file(fileInput, tmpFilename)
                else:
                    self._process_decrypt_file(fileInput, tmpFilename)
                self._metrics.process_file(fileInput)
        except Exception:
            logging.error('Failed to process file: ' + fileInput)

    def _process_encrypt_file(self, fileInput, tmpFilename):
        encType = encrypt_file(fileInput,
                               tmpFilename,
                               self._password,
                               self._fileBufferSize)
        fileInputEnc = fileInput + ENCRYPTED_EXT
        os.rename(fileInput, fileInputEnc)
        self._fileToEncTypeDict[fileInputEnc] = encType

    def _process_decrypt_file(self, fileInput, tmpFilename):
        if (fileInput[-len(ENCRYPTED_EXT):] == ENCRYPTED_EXT
                and fileInput in self._fileToEncTypeDict):
            decrypt_file(fileInput,
                         tmpFilename,
                         self._password,
                         self._fileBufferSize,
                         self._fileToEncTypeDict[fileInput])
            os.rename(fileInput, fileInput[:-len(ENCRYPTED_EXT)])

    # Encrypt/Decrypt filenames
    # =================================================================

    def _process_file_name(self, fileInput):
        try:
            if (_get_filename(fileInput) != FolderEncryptor.METADATA_FILE
                    and fileInput != self.folderLocation and os.access(fileInput, os.W_OK)):
                inputName = _get_filename(fileInput)
                outputName = None
                if self._encryptFiles:
                    outputName = self._process_encrypt_filename(fileInput, inputName)
                else:
                    outputName = self._process_decrypt_filename(fileInput, inputName)
                if outputName:
                    fileOutput = os.path.join(_get_parent(fileInput), outputName)
                    os.rename(fileInput, fileOutput)
                    self._metrics.process_filename(fileOutput)
        except Exception:
            logging.error('Failed to process filename: ' + fileInput)

    def _process_encrypt_filename(self, fileInput, inputName):
        outputName = self._fileCreation.get_filename()
        self._uuidToFilenameDict[outputName] = encrypt_bytes(str.encode(self._password),
                                                             str.encode(inputName),
                                                             False)
        return outputName

    def _process_decrypt_filename(self, fileInput, inputName):
        if inputName in self._uuidToFilenameDict:
            uuidFilename = self._uuidToFilenameDict[inputName]
            outputName = decrypt_bytes(str.encode(self._password), uuidFilename, False).decode()
            return outputName

    # Password Verification
    # =================================================================

    def _verify_password(self, password):
        if self._encryptFiles:
            self._handle_verify_pwd_encrypt(password)
        else:
            self._handle_verify_pwd_decrypt(password)

    def _handle_verify_pwd_encrypt(self, password):
        encryptedPassword = encrypt_bytes(str.encode(self._password),
                                          str.encode(_DataStore.PASSWORD_VERIFIER_KEY),
                                          False)
        self._datasource.save_value(_DataStore.PASSWORD_VERIFIER_KEY, encryptedPassword)

    def _handle_verify_pwd_decrypt(self, password):
        try:
            encryptedPassword = self._datasource.get_value(_DataStore.PASSWORD_VERIFIER_KEY)
            decryptedPasswordEnc = decrypt_bytes(str.encode(self._password),
                                                 encryptedPassword,
                                                 False)
            if decryptedPasswordEnc.decode() == _DataStore.PASSWORD_VERIFIER_KEY:
                return None
        except Exception:
            pass
        raise InvalidPasswordError

    # Utilities
    # =================================================================

    def _check_args(self,
                    folderLocation,
                    password,
                    passwordFile,
                    verifyPassword,
                    metricsEnabled,
                    maxThreads,
                    memory,
                    memoryMultiplier):

        self._check_type(folderLocation, "folderLocation", str)
        if not(os.path.isdir(folderLocation)):
            raise InvalidArgumentError("folderLocation",
                                       "Location [{0}] does not exist".format(folderLocation))

        self._check_type(passwordFile, "passwordFile", bool)
        if passwordFile and not(os.path.exists(password)):
            raise InvalidArgumentError("password",
                                       "Path [{0}] does not exist".format(folderLocation))

        password = password if not(passwordFile) else _read_file(password, "r+")
        self._check_type(password, "password", str)
        if len(password) > MAX_PASS_LENGTH:
            raise InvalidArgumentError("password",
                                       "Length exceeds [{0}]".format(MAX_PASS_LENGTH))

        self._check_type(verifyPassword, "verifyPassword", bool)
        self._check_type(metricsEnabled, "metricsEnabled", bool)
        self._check_type(maxThreads, "maxThreads", int)
        self._check_type(memory, "memory", int)
        self._check_type(memoryMultiplier, "memoryMultiplier", float)

    def _check_type(self, inputVal, inputStr, typee):
        if not(isinstance(inputVal, typee)):
            raise InvalidArgumentError(inputStr, "arg is not a " + str(typee))

    def _calc_default_buffer(self, threadCount, memory, memoryMultiplier=0.75):
        memoryToUse = memory if memory > 0 else psutil.virtual_memory().available
        memoryBytesPerThread = (memoryToUse * memoryMultiplier) // threadCount
        return int(memoryBytesPerThread - (memoryBytesPerThread % 16))
