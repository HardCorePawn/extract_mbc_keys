#!/usr/bin/python

# extract_mbc_keys.pyw
# Extract Public and Private Keys from a MultiBit Classic wallet
# Copyright (C) 2017, HCP
# All rights reserved.
#
# Based on decrypt_bitcoinj_seed.pyw
# Copyright (C) 2014, 2016 Christopher Gurnee
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# If you find this program helpful, please consider a small
# donation to the developer at the following Bitcoin address:
#
#           1NyVDDmhZPcyKhyrkiUFZbqPPuiYxwTujb
#
#                      Thank You!

from __future__ import print_function

__version__ =  '0.4.0'

import hashlib, sys, os, getpass
import aespython.key_expander, aespython.aes_cipher, aespython.cbc_mode
import wallet_pb2, binascii, bitcoin
import pylibscrypt
        
sha256 = hashlib.sha256
md5    = hashlib.md5


key_expander = aespython.key_expander.KeyExpander(256)

def aes256_cbc_decrypt(ciphertext, key, iv):
    """decrypts the ciphertext using AES256 in CBC mode

    :param ciphertext: the encrypted ciphertext
    :type ciphertext: str
    :param key: the 256-bit key
    :type key: str
    :param iv: the 128-bit initialization vector
    :type iv: str
    :return: the decrypted ciphertext, or raises a ValueError if the key was wrong
    :rtype: str
    """
    block_cipher  = aespython.aes_cipher.AESCipher( key_expander.expand(map(ord, key)) )
    stream_cipher = aespython.cbc_mode.CBCMode(block_cipher, 16)
    stream_cipher.set_iv(bytearray(iv))
    plaintext = bytearray()
    for i in xrange(0, len(ciphertext), 16):
        plaintext.extend( stream_cipher.decrypt_block(map(ord, ciphertext[i:i+16])) )
    padding_len = plaintext[-1]
    # check for PKCS7 padding
    if not (1 <= padding_len <= 16 and plaintext.endswith(chr(padding_len) * padding_len)):
        raise ValueError('incorrect password')
    return str(plaintext[:-padding_len])


multibit_hd_password = None
def load_wallet(wallet_file, get_password_fn):
    """load and if necessary decrypt a bitcoinj wallet file

    :param wallet_file: an open bitcoinj wallet file
    :type wallet_file: file
    :param get_password_fn: a callback returning a password that's called iff one is required
    :type get_password_fn: function
    :return: the Wallet protobuf message or None if no password was entered when required
    :rtype: wallet_pb2.Wallet
    """

    wallet_file.seek(0)
    magic_bytes = wallet_file.read(12)
    
    wallet_file.seek(0, os.SEEK_END)
    wallet_size = wallet_file.tell()
    wallet_file.seek(0)

    if magic_bytes[2:6] != b"org." and wallet_size % 16 == 0:
        takes_long = not pylibscrypt._done  # if a binary library wasn't found, this'll take a while

        ciphertext = wallet_file.read()
        assert len(ciphertext) % 16 == 0

        password = get_password_fn(takes_long)
        if not password:
            return None

        # Derive the encryption key
        salt = '\x35\x51\x03\x80\x75\xa3\xb0\xc5'
        key  = pylibscrypt.scrypt(password.encode('utf_16_be'), salt, olen=32)

        # Decrypt the wallet ( v0.5.0+ )
        try:
            plaintext = aes256_cbc_decrypt(ciphertext[16:], key, ciphertext[:16])
            if plaintext[2:6] != b"org.":
                raise ValueError('incorrect password')
        except ValueError as e:
            if e.args[0] == 'incorrect password':

                # Decrypt the wallet ( < v0.5.0 )
                iv = '\xa3\x44\x39\x1f\x53\x83\x11\xb3\x29\x54\x86\x16\xc4\x89\x72\x3e'
                plaintext = aes256_cbc_decrypt(ciphertext, key, iv)

        global multibit_hd_password
        multibit_hd_password = password

    # Else it's not whole-file encrypted
    else:
        print("File NOT Encrypted")
        password  = None
        plaintext = wallet_file.read()

    # Parse the wallet protobuf
    pb_wallet = wallet_pb2.Wallet()
    try:
        pb_wallet.ParseFromString(plaintext)
    except Exception as e:
        msg = 'not a wallet file: ' + str(e)
        if password:
            msg = "incorrect password (or " + msg + ")"
        raise ValueError(msg)
    
    f = open('parsed_wallet.txt','w')
    f.write(pb_wallet.__str__())
    f.close()
    
    print("--------------------------------------------------------------------------------")
    
    return pb_wallet

def extract_keys(pb_wallet, get_password_fn):
    """extract and if necessary decrypt (w/scrypt) the address/keys from a MultiBit Classic wallet protobuf

    :param pb_wallet: a Wallet protobuf message
    :type pb_wallet: wallet_pb2.Wallet
    :param get_password_fn: a callback returning a password that's called if one is required
    :type get_password_fn: function
    :return: All the Public Addresses/Private Key Pairs in the wallet
    :rtype: list of Public Address and matching Private Key pairs
    """
    keys = []

    if pb_wallet.encryption_type == 2:
        
        print("Keys are encrypted")
        
        takes_long = not pylibscrypt._done  # if a binary library wasn't found, this'll take a while
        password = get_password_fn(takes_long)
        if not password:
            return None
                
        salt = pb_wallet.encryption_parameters.salt
        #salt = '\x35\x51\x03\x80\x75\xa3\xb0\xc5'
        dkey = pylibscrypt.scrypt(password.encode('utf_16_be'), salt, olen=32)
        
        for enckeys in pb_wallet.key:
          
          ciphertext = enckeys.encrypted_data.encrypted_private_key
          iv = enckeys.encrypted_data.initialisation_vector
          
          privkey = aes256_cbc_decrypt(ciphertext, dkey, iv)
        
          print("--------------------------------------------------------------------------------")
          thePubKey = bitcoin.pubtoaddr(enckeys.public_key)
          thePrivKey = bitcoin.encode_privkey(privkey, 'wif_compressed')
          theAddress = bitcoin.privtoaddr(thePrivKey)
          
          #if the addresses don't match, use the uncompressed key
          if theAddress != thePubKey:
            thePrivKey = bitcoin.encode_privkey(privkey, 'wif')
                        
          print("")
          print("PubKey: " + thePubKey)
          print("PrivKey: " + thePrivKey)
          keys.append([thePubKey,thePrivKey])

    elif pb_wallet.encryption_type == 1:
    
        print("Keys NOT encrypted")
     
        for enckeys in pb_wallet.key:
          thePubKey = bitcoin.pubtoaddr(enckeys.public_key)
          thePrivKey = bitcoin.encode_privkey(enckeys.secret_bytes, 'wif_compressed')
          theAddress = bitcoin.privtoaddr(thePrivKey)
          
          #if the addresses don't match, use the uncompressed key
          if theAddress != thePubKey:
            thePrivKey = bitcoin.encode_privkey(enckeys.secret_bytes, 'wif')
                        
          print("")
          print("PubKey: " + thePubKey)
          print("PrivKey: " + thePrivKey)
          keys.append([thePubKey,thePrivKey])
          
    print("")
    print("--------------------------------------------------------------------------------")
    
    return keys


if __name__ == '__main__':

    padding      = 6     # GUI widget padding
    progress_bar = None  # GUI progress bar

    # command-line specific code
    if len(sys.argv) > 1:

        if len(sys.argv) != 2 or sys.argv[1].startswith('-'):
            sys.exit('usage: foo.pyw mbclassic-wallet-file')

        wallet_file = open(sys.argv[1], 'rb')

        def get_password_factory(prompt):
            def get_password(takes_long_arg_ignored):  # must return unicode
                encoding = sys.stdin.encoding or 'ASCII'
                if 'utf' not in encoding.lower():
                    print('terminal does not support UTF; passwords with non-ASCII chars might not work', file=sys.stderr)
                password = getpass.getpass(prompt + ' ')
                if isinstance(password, str):
                    password = password.decode(encoding)  # convert from terminal's encoding to unicode
                return password
            return get_password

        # These functions differ between command-line and GUI runs
        get_password  = get_password_factory('This wallet file is encrypted, please enter its password:')
        get_pin       = get_password_factory("This wallet's seed is encrypted with a PIN or password, please enter it:")
        display_error = lambda msg: print(msg, file=sys.stderr)

    # GUI specific code
    else:

        import Tkinter as tk, ttk, tkFileDialog, tkSimpleDialog, tkMessageBox
        from Tkinter import *
        
        root = tk.Tk(className='MBC Key Extractor')  # initialize the library
        root.withdraw()                                 # but don't display a window yet

        wallet_file = tkFileDialog.askopenfile('rb', title='Load wallet file')
        if not wallet_file:
            sys.exit('no wallet file selected')

        # Initializes the main window and displays a progress bar
        def init_window(no_progress = False):
            global progress_bar
            if not progress_bar:
                tk.Label(text='WARNING: PrivKey information is sensitive, carefully protect it and do not share', fg='red').pack(padx=padding, pady=padding)
                tk.Label(text='Addrs/Keys:').pack(side=tk.LEFT, padx=padding, pady=padding)
                if not no_progress:
                    progress_bar = ttk.Progressbar(length=480, orient='horizontal', mode='indeterminate')
                    progress_bar.pack(side=tk.LEFT, padx=padding, pady=padding)
                root.deiconify()
            root.update()

        # These functions differ between command-line and GUI runs
        def get_password(takes_long):  # must return Unicode
            password = tkSimpleDialog.askstring('Password', 'This wallet file is encrypted, please enter its password:', show='*')
            if takes_long:
                init_window()  # display the progress bar if this could take a while
            return password.decode('ASCII') if isinstance(password, str) else password
        def get_pin(takes_long):       # must return Unicode
            pin = tkSimpleDialog.askstring('Password', "This wallet's seed is encrypted with a PIN or password, please enter it:", show='*')
            if takes_long:
                init_window()  # display the progress bar if this could take a while
            return pin.decode('ASCII') if isinstance(pin, str) else pin
        def display_error(msg):
            return tkMessageBox.showerror('Error', msg)

    # Load (and possibly decrypt) the wallet, retrying on bad passwords
    while True:
        try:
            wallet = load_wallet(wallet_file, get_password)
            if not wallet:  # if no password was entered
                sys.exit('canceled')
            break
        except ValueError as e:
            display_error(str(e))
            if not e.args[0].startswith('incorrect password'):
                raise

    extra_keys_warning = None

    keys = extract_keys(wallet, get_password)
    
    # command-line specific code
    if len(sys.argv) > 1:
        if extra_keys_warning:
            print('\nWARNING:')
            print(extra_keys_warning)
        print('\nWARNING: PrivKey information is sensitive, carefully protect it and do not share')
        print('Extracted Addrs/Keys:\n', keys)

    # GUI specific code
    else:

        if extra_keys_warning:
            tkMessageBox.showwarning('Warning', extra_keys_warning)

        # Create the text box that will hold the mnemonic
        entry = tk.Text(root)
        for x in keys:
          entry.insert(INSERT, "PublicKey: " + x[0] + "\n")
          entry.insert(END, "PrivKey: " + x[1] + "\n")
          entry.insert(END, "-------------------------------------------------------------------------------\n")
        
        entry.config(state=DISABLED)
        # Replace the progress bar if the window already exists; else init the window
        if progress_bar:
            progress_bar.pack_forget()
        else:
            init_window(no_progress=True)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=padding, pady=padding)

        root.deiconify()
        entry.focus_set()
        root.mainloop()
