#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import argparse
import multiprocessing

from pathlib import Path
from pyFolderLock import MultiFolderEncryptor, InvalidPasswordError, InvalidArgumentError

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

# ================================================================
#
# Main
#
# ================================================================


def main():
    '''
    Takes input for password + folder(s)
    Ex.  pyFolderLockCmd.py TEST123 E:/testtttt/testFolder "E:/testtttt/Everything Needed"
    Ex.  pyFolderLockCmd.py TEST123 "E:/testtttt/Everything Needed"
    Ex.  pyFolderLockCmd.py --pwdfile E:/testtttt/pwd.txt E:/testtttt/testFolder
    Things to do:
        - handle single file case?
        - test multi file case
        - implement pyinstaller?
    '''
    parser = argparse.ArgumentParser(description='Encrypts folder contents with provided password.')

    # optional arg to specify password field is a file which has password inside it
    parser.add_argument("-pf",
                        "--pwdfile",
                        action='store_true',
                        help="uses password stored in file (to avoid cmdline history)")

    # optional arg to enable password verification
    parser.add_argument("-v",
                        "--verify",
                        action='store_true',
                        help="""Checks if password is correct before decrypting.
                                Must have been run on initial encrypt.
                               (keep in mind, this does provide an avenue for brute forcing)""")

    # optional arg to disable metrics (slightly faster performance and no logging)
    parser.add_argument("-dm",
                        "--disableMetrics",
                        action='store_true',
                        help="""Disables metrics thread
                                (no progress logging, and no extra thread taking up resources)""")

    # optional arg to specify thread count
    parser.add_argument("-t",
                        "--threads",
                        type=int,
                        default=multiprocessing.cpu_count(),
                        help="""Number of threads to use. Defaults to CPU count.""")

    # optional arg to specify max memory
    parser.add_argument("-m",
                        "--memory",
                        type=int,
                        default=0,
                        help="""Specify max memory this can use. Defaults to dynamic allocation.""")

    # arg for password
    def _check_password(password):
        if len(password) <= 0:
            raise argparse.ArgumentTypeError("%s is an invalid password" % password)
        return password

    parser.add_argument("password",
                        type=_check_password,
                        help="password which will be used for the encryption/decryption")

    # arg for folder(s)
    def _check_folder(folder):
        if not(os.path.isdir(folder)):
            raise argparse.ArgumentTypeError("%s is an invalid folder" % folder)
        return folder

    parser.add_argument("folders",
                        type=_check_folder,
                        nargs="*",
                        help="folder whose contents will be encrypted/decrypted")

    args = parser.parse_args()

    # handle specifying password is a file
    if args.pwdfile:
        if not(os.path.exists(args.password)):
            raise argparse.ArgumentTypeError("%s does not exist" % args.password)

    # logging setup
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    # run
    MultiFolderEncryptor(args.folders,
                         args.password,
                         passwordFile=args.pwdfile,
                         verifyPassword=args.verify,
                         maxThreads=args.threads,
                         memory=args.memory,
                         metricsEnabled=not(args.disableMetrics)).run()


if __name__ == '__main__':
    main()
