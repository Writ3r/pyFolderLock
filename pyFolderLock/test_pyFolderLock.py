#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import os
import inspect
import shutil

from pathlib import Path
from pyFolderLock import FolderEncryptor, MultiFolderEncryptor
from pyFolderLock import InvalidPasswordError, InvalidArgumentError


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


class TestPyFolderLock(unittest.TestCase):
    """
    ways to improve tests:
    - make json of files to build?
    - get hash of file on enc/decrypt and compare
    """
    WORKING_DIR = _get_parent(inspect.getfile(inspect.currentframe()))
    TEST_WORKING_FOLDER = os.path.join(WORKING_DIR, 'TEST_WORKING_FOLDER')
    PASSWORD_FILE = os.path.join(TEST_WORKING_FOLDER, 'PASSWORDTEST.txt')
    TEST_ENCRYPT_FOLDER = os.path.join(TEST_WORKING_FOLDER, 'TEST_ENC_FOLDER')

    TEST_DIR = os.path.join(TEST_ENCRYPT_FOLDER, 'TEST_DATA')
    TEST_DIR2 = os.path.join(TEST_ENCRYPT_FOLDER, 'TEST_DATA2')

    TEST_FOLDER_LIST = [
        os.path.join(TEST_DIR, 'TESTFOL1'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2', 'TESTFOL3'),
        os.path.join(TEST_DIR, 'TESTFOL1', 'TESTFOL2', 'TESTFOL3', 'TESTFOL4'),
        os.path.join(TEST_DIR, 'TESTFOL5'),
        os.path.join(TEST_DIR2, 'TESTFOL1'),
        os.path.join(TEST_DIR2, 'TESTFOL1', 'TESTFOL2'),
        os.path.join(TEST_DIR2, 'TESTFOL1', 'TESTFOL2', 'TESTFOL3'),
    ]
    TEST_FILE_MAP = {
        'TEST1.txt': 'I AM ENC1',
        'TEST2.txt': 'I AM ENC2',
        'TEST3.txt': 'I AM ENC3',
        'TEST4.txt': 'I AM ENC4',
        'TEST5.txt': 'I AM ENC5',
    }

    def setUp(self):
        # destroy any possible files
        self.tearDown()
        # create basic test folder
        os.mkdir(TestPyFolderLock.TEST_WORKING_FOLDER)
        os.mkdir(TestPyFolderLock.TEST_ENCRYPT_FOLDER)
        os.mkdir(TestPyFolderLock.TEST_DIR)
        os.mkdir(TestPyFolderLock.TEST_DIR2)
        for folder in TestPyFolderLock.TEST_FOLDER_LIST:
            os.mkdir(folder)
            for key in TestPyFolderLock.TEST_FILE_MAP:
                _write_file(os.path.join(folder, key),
                            TestPyFolderLock.TEST_FILE_MAP[key],
                            "w")

    def tearDown(self):
        if os.path.exists(TestPyFolderLock.TEST_WORKING_FOLDER):
            shutil.rmtree(TestPyFolderLock.TEST_WORKING_FOLDER)

    def test_00_encrypt_byte_basic(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR, "PASSWORD111").run()
        # check that all files/dirs are diff
        self.check_dirs_not_normal()

    def test_01_decrypt_byte_basic(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR, "PASSWORD111").run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR, "PASSWORD111").run()
        # check that all files/dirs are back to normal
        self.check_dirs_normal()

    def test_00_multi_folders(self):
        # encrypt
        MultiFolderEncryptor([TestPyFolderLock.TEST_DIR, TestPyFolderLock.TEST_DIR2],
                             "PASSWORD111").run()
        # check that all files/dirs are not normal
        self.check_dirs_not_normal(multi=True)
        # decrypt
        MultiFolderEncryptor([TestPyFolderLock.TEST_DIR, TestPyFolderLock.TEST_DIR2],
                             "PASSWORD111").run()
        # check that all files/dirs are normal
        self.check_dirs_normal(multi=True)

    def test_02_pwdFile(self):
        # write password file
        _write_file(TestPyFolderLock.PASSWORD_FILE, 'I AM A PASSWORD', "w")
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        TestPyFolderLock.PASSWORD_FILE,
                        passwordFile=True).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        'I AM A PASSWORD').run()
        # check normal
        self.check_dirs_normal()
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          TestPyFolderLock.PASSWORD_FILE + '.invalid',
                          passwordFile=True)

    def test_03_decrypt_pwdVerify(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        verifyPassword=True).run()
        # decrypt
        self.assertRaises(InvalidPasswordError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          verifyPassword=True)
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          verifyPassword=10)

    def test_04_metricsEnabled(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        metricsEnabled=False).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        metricsEnabled=True).run()
        # check normal
        self.check_dirs_normal()
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          metricsEnabled=10)

    def test_05_maxThreads(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=4).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1).run()
        # check normal
        self.check_dirs_normal()
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          maxThreads="a")

    def test_06_memory(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        memory=4000).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        memory=5000).run()
        # check normal
        self.check_dirs_normal()
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          memory="a")

    def test_07_memoryMultiplier(self):
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        memoryMultiplier=0.4).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        memoryMultiplier=0.5).run()
        # check normal
        self.check_dirs_normal()
        # check invalid arg
        self.assertRaises(InvalidArgumentError,
                          FolderEncryptor,
                          TestPyFolderLock.TEST_DIR,
                          "PASSWORD111",
                          memoryMultiplier="a")

    def test_08_stream_encryption(self):
        largeFile = os.path.join(TestPyFolderLock.TEST_DIR, 'LARGE_TEST.txt')
        # make large file
        f = open(largeFile, "wb")
        f.seek(536870912-1)
        f.write(b"\0")
        f.close()
        # encrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1,
                        memory=268435456).run()
        # decrypt
        FolderEncryptor(TestPyFolderLock.TEST_DIR,
                        "PASSWORD1113",
                        maxThreads=1,
                        memory=268435456).run()
        # check normal
        self.assertTrue(os.path.exists(largeFile))

    def check_dirs_normal(self, multi=False):
        """check that all files/dirs are back to normal"""
        folders = [TestPyFolderLock.TEST_DIR]
        if multi:
            folders.append(TestPyFolderLock.TEST_DIR2)
        for folderTest in folders:
            for root, dirs, files in os.walk(folderTest):
                for folder in dirs:
                    self.assertTrue('TEST' in folder)
                for filee in files:
                    self.assertTrue('TEST' in filee)
                    self.assertTrue('I AM' in _read_file(os.path.join(root, filee), "r+"))

    def check_dirs_not_normal(self, multi=False):
        """check that all files/dirs are different"""
        folders = [TestPyFolderLock.TEST_DIR]
        if multi:
            folders.append(TestPyFolderLock.TEST_DIR2)
        for folderTest in folders:
            for root, dirs, files in os.walk(folderTest):
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
