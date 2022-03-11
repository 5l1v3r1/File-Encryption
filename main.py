from cryptography.fernet import Fernet
import argparse
import sys

def file_extension_check(filename:str,extension:str):
    """
    :param filename: The filename to check for the existence of the extension.
    :param extension: Checked extension. There must be a dot at the beginning of the plugin. (Sample ".txt")
    :return: filename
    """
    extension_length= (len(extension)) * -1
    if filename[extension_length:] != extension:
        filename = filename + extension

    return filename

def write_key(key_file_name:str = "key.key"):
    """
    :param name_keyfile: Filename to print the key. (Sample "key", "abc", "key.key", "abc.key")
    :return: key
    """
    key = Fernet.generate_key()
    name_keyfile = file_extension_check(key_file_name, ".key")

    with open(name_keyfile, "wb") as keyfile:
        keyfile.write(key)

    return key

def load_key(path_keyfile:str = "key.key"):
    """
    :param path_keyfile: The filename to call the previously generated key for decryption. (Sample "key", "abc", "key.key", "abc.key")
    :return: key
    """
    path_keyfile = file_extension_check(path_keyfile, ".key")

    try:
        with open(path_keyfile, "rb") as keyfile:
            return keyfile.read().decode()
    except FileNotFoundError:
        raise FileNotFoundError("FileNotFoundError: You need the 'key.key' file to be able to decrypt or encrypt the file. Make sure it's in the same directory as the target folder. If you don't have the 'key.key' create it using the '-g' parameter and encrypt your file. To decrypt an encrypted file, you must already have the 'key.key' file.")

def encrypt(filename:str, key:str):
    """
    :param filename: The file path to be encrypted.
    :param key: Key to encrypt the file.
    """
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)

    enc_filename = "enc_" + filename
    with open(enc_filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename:str, key:str):
    """
    :param filename: The file path to be decrypted.
    :param key: The key to decrypt the file.
    """

    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)

    filename = "dec_" + filename
    with open(filename, "wb") as file:
        file.write(decrypted_data)

# Project Information
parser = argparse.ArgumentParser(prog = "Data-Encryption",
                                 description = "This app is for generating key and encrypting and decrypting files.",
                                 epilog = "This software was created by Metin Ilgar Mutlu.")

parser.add_argument("file", help="File to encrypt/decrypt")
parser.add_argument("-k", "--key", help = "It is used to use the key that already exists.")
parser.add_argument("-g", "--generate-key", action="store_true",
                    help="It is used to generate a new key. If this parameter is used, the 'key' parameter is not needed.")

# Encryption
parser.add_argument("-e", "--encrypt",
                    help = """Use this parameter if you want to encrypt file.\n
                     Example: """,
                    action="store_true")
# Decryption
parser.add_argument("-d", "--decrypt", help = """Use this parameter if you want to decrypt the file.\n
                    Example: """,
                    action="store_true")

data = parser.parse_args()

file = data.file
generate_key = data.generate_key
existing_key = data.key


if existing_key and generate_key:
    raise TypeError("Please select the key ('-k a.key') or create a new key ('-g').")
elif generate_key:
    key = write_key()
elif existing_key:
    key = load_key(existing_key)
else:
    raise TypeError("Please select the key ('-k a.key') or create a new key ('-g').")

if data.encrypt and data.decrypt:
    raise TypeError('Please specify whether you want to encrypt or decrypt the file. (Example "-e" or "-d")')
elif data.encrypt:
    encrypt(file,key)
elif data.decrypt and not existing_key:
    raise TypeError("You need to enter the existing key to decrypt the file. ('-k name.key')")
elif data.decrypt and existing_key:
    decrypt(file, key)
else:
    raise TypeError("Please specify whether you want to encrypt or decrypt the file. (Example '-e' or '-d')")