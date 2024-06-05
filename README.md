# PasswordManager_v2

An application to store you're favorite websites/applications username and passwords

Prerequisities: Install the following pip packages: cryptography pyperclip hashlib, logging.

This application meant to run in a Windows OS.

This application when running for the first time will ask the user to create a user/password. After that the application will create a key for the user to encrypt and decrypt all passwords that the user will save.

The users password will be stored in credentials.json file and will be hash with a one way SHA3 512 bit. The passwords the user will save are stored in a passwords.json file and are hashed as well with a key created during the signup process, if the key is deleted the passwords are unable to recover. If the key is stolen than a hacker can decrypt the passwords.

This version of the application has better security, supports multiple users, 3 logs rotation of 1MB each and more functionalities.

All 3 files have to be in the same directory.
