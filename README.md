# pyFolderLock
Recursively encrypts files in folders. Useful for keeping vital information safe from hackers. Great for people who want windows 10 professional folder encryption functionality, but don't want to pay for it.

## Supported OS
Wrote all the code on windows, but the code should be OS independent. Let me know if it fails to run in linux.

## Setup
- Make sure your environment has the necessary pip installs inside requirements.txt
- If you are importing the objects into your python modules, make sure this module is on your python path.

## Ways to use
- import pyFolderLock's FolderEncryptor or MultiFolderEncryptor, build the object, and run it.
- call the [project cli interface file](https://github.com/Writ3r/pyFolderLock/blob/main/pyFolderLock/pyFolderLockCli.py) with stated args
