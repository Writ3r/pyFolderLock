#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import os
import inspect
import shutil

from pathlib import Path

from pyLock import FolderEncryptor, InvalidPasswordError, InvalidArgumentError


# Utilities
# =================================================================


def _read_file(path, mode='rb'):
    with open(path, mode) as ifp:
        return ifp.read()


def _write_file(path, content, mode='wb'):
    with open(path, mode) as ofp:
        ofp.write(content)


def _get_filename(filepath):
    return str(Path(filepath).name)


def _get_parent(filepath):
    return str(Path(filepath).parent)


# Tests
# =================================================================


class TestStringMethods(unittest.TestCase):
    WORKING_DIR = _get_parent(inspect.getfile(inspect.currentframe()))
    TEST_DIR = os.path.join(WORKING_DIR, 'TEST_DATA')
    TEST_FOLDER_LIST = [
        os.path.join(TEST_DIR, 'TESTFOL1'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2', 'TESTFOL3'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2', 'TESTFOL3', 'TESTFOL4'),
        os.path.join(TEST_DIR, 'TESTFOL5'),
        os.path.join(TEST_DIR, 'TESTFOL6'),
    ]
    TEST_FILE_MAP = {
        'TEST1.txt': 'I AM ENC1',
        'TEST2.txt': 'I AM ENC2',
        'TEST3.txt': 'I AM ENC3',
        'TEST4.txt': 'I AM ENC4',
        'TEST5.txt': 'I AM ENC5',
    }
    PASSWORD_FILE = os.path.join(WORKING_DIR, 'PASSWORDTEST.txt')

    def setUp(self):
        # destroy any possible files
        self.tearDown()
        # create basic test folder
        os.mkdir(TestStringMethods.TEST_DIR)
        for folder in TestStringMethods.TEST_FOLDER_LIST:
            os.mkdir(folder)
            for key in TestStringMethods.TEST_FILE_MAP:
                _write_file(os.path.join(folder, key),
                            TestStringMethods.TEST_FILE_MAP[key],
                            "w")

    def tearDown(self):
        if os.path.exists(TestStringMethods.TEST_DIR):
            shutil.rmtree(TestStringMethods.TEST_DIR)
        if os.path.exists(TestStringMethods.PASSWORD_FILE):
            os.remove(TestStringMethods.PASSWORD_FILE)

    def test_00_encrypt_byte_basic(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR, "PASSWORD111").run()
        # check that all files/dirs are diff
        self.check_dirs_not_normal()

    def test_01_decrypt_byte_basic(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR, "PASSWORD111").run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR, "PASSWORD111").run()
        # check that all files/dirs are back to normal
        self.check_dirs_normal()

    def test_02_pwdFile(self):
        # write password file
        _write_file(TestStringMethods.PASSWORD_FILE, 'I AM A PASSWORD', "w")
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        TestStringMethods.PASSWORD_FILE,
                        passwordFile=True).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        'I AM A PASSWORD').run()
        self.check_dirs_normal()

    def test_03_decrypt_pwdVerify(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR, 
                        "PASSWORD1113",
                        verifyPassword=True).run()
        # decrypt
        self.assertRaises(InvalidPasswordError,
                          FolderEncryptor,
                          TestStringMethods.TEST_DIR,
                          "PASSWORD111",
                          verifyPassword=True)

    def test_04_metricsEnabled(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        metricsEnabled=False).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        metricsEnabled=True).run()
        self.check_dirs_normal()

    def test_05_maxThreads(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=4).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1).run()
        self.check_dirs_normal()

    def test_06_memory(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        memory=4000).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=5000).run()
        self.check_dirs_normal()

    def test_07_memoryMultiplier(self):
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        memoryMultiplier=0.4).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        memoryMultiplier=0.5).run()
        self.check_dirs_normal()

    def test_08_stream_encryption(self):
        largeFile = os.path.join(TestStringMethods.TEST_DIR, 'LARGE_TEST.txt')
        # make large file
        f = open(largeFile, "wb")
        f.seek(1073741824-1)
        f.write(b"\0")
        f.close()
        # encrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1,
                        memory=836870912).run()
        # decrypt
        FolderEncryptor(TestStringMethods.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1,
                        memory=836870912).run()
        self.assertTrue(os.path.exists(largeFile))

    def check_dirs_normal(self):
        # check that all files/dirs are back to normal
        for root, dirs, files in os.walk(TestStringMethods.TEST_DIR):
            for folder in dirs:
                self.assertTrue('TEST' in folder)
            for filee in files:
                self.assertTrue('TEST' in filee)
                self.assertTrue('I AM' in _read_file(os.path.join(root, filee), "r+"))

    def check_dirs_not_normal(self):
        for root, dirs, files in os.walk(TestStringMethods.TEST_DIR):
            for folder in dirs:
                self.assertFalse('TEST' in folder)
            for filee in files:
                self.assertFalse('TEST' in filee)
                try:
                    self.assertFalse('I AM' in _read_file(os.path.join(root, filee), "r+"))
                except Exception:
                    pass

if __name__ == '__main__':
    unittest.main()
