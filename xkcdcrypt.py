#!/usr/bin/env python3
import argon2
import argparse
import os
import tarfile
from getpass import getpass
from io import BytesIO
from miscreant.aes.siv import SIV
from pathlib import Path
from secrets import choice
from tempfile import mkstemp, TemporaryDirectory


class XkcdCrypt:
    def __init__(self: object, in_path: str) -> None:
        self.SALT_SIZE = 16  # Size of salt in bytes
        self.NONCE_SIZE = 16  # Size of nonce in bytes
        self.in_path = in_path

    def encrypt(self: object) -> [bytes, str]:
        passphrase = self._gen_xkcd_phrase()
        salt = os.urandom(self.SALT_SIZE)
        key = self._derive_key(passphrase.encode('utf-8'), salt)
        siv = SIV(key)
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = salt + nonce + siv.seal(self._archive(), [nonce])
        return ciphertext, passphrase

    @staticmethod
    def _gen_xkcd_phrase() -> str:
        with open('words.txt', 'r') as word_file:
            wordlist = word_file.read()
        wordlist = wordlist.split()
        xkcdphrase = [choice(wordlist)
                      for __ in range(4)]  # Words in passphrase
        return '-'.join(xkcdphrase)

    @staticmethod
    def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
        return argon2.low_level.hash_secret_raw(
            passphrase,
            salt,
            # Time cost in iterations.
            time_cost=2,
            # Memory cost in kibibytes.
            memory_cost=102400,
            # Number of parallel threads.
            parallelism=8,
            # Length of the hash in bytes.
            hash_len=32,
            # Resistance to timing attacks and tradeoff attacks.
            type=argon2.low_level.Type.ID)

    def _archive(self: object) -> bytes:
        with BytesIO() as buffer:
            with tarfile.open(fileobj=buffer, mode='x:bz2') as arc_file:
                arc_file.add(self.in_path)
            buffer.seek(0)
            return buffer.read()

    def decrypt(self: object, passphrase: bytes) -> None:
        with open(self.in_path, 'rb') as in_file:
            salt = in_file.read(self.SALT_SIZE)
            key = self._derive_key(passphrase, salt)
            siv = SIV(key)
            nonce = in_file.read(self.NONCE_SIZE)
            plaintext = siv.open(in_file.read(), [nonce])
        self._extract(plaintext)

    def _extract(self: object, plaintext: bytes) -> None:
        dest = self.in_path.parent.joinpath(self.in_path.stem)
        with TemporaryDirectory() as temp_dir:
            with BytesIO(plaintext) as buffer:
                with tarfile.open(fileobj=buffer, mode='r:bz2') as arc_file:
                    def is_within_directory(directory, target):
                        
                        abs_directory = os.path.abspath(directory)
                        abs_target = os.path.abspath(target)
                    
                        prefix = os.path.commonprefix([abs_directory, abs_target])
                        
                        return prefix == abs_directory
                    
                    def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                    
                        for member in tar.getmembers():
                            member_path = os.path.join(path, member.name)
                            if not is_within_directory(path, member_path):
                                raise Exception("Attempted Path Traversal in Tar File")
                    
                        tar.extractall(path, members, numeric_owner=numeric_owner) 
                        
                    
                    safe_extract(arc_file, temp_dir)
            temp = Path(temp_dir).joinpath(dest.name)
            os.rename(temp, dest)


def main() -> None:
    parser = argparse.ArgumentParser(description='Encrypt & decrypt files.')
    parser.add_argument('file', help='The file to be encrypted or decrypted.')
    in_path = Path(parser.parse_args().file)
    xc = XkcdCrypt(in_path)
    if XC_SUFFIX != in_path.suffix:
        try:
            ciphertext, passphrase = xc.encrypt()
            out_path = in_path.with_suffix(in_path.suffix + XC_SUFFIX)
            stemp_fd, stemp_path = mkstemp()
            os.write(stemp_fd, ciphertext)
            os.fsync(stemp_fd)
            os.close(stemp_fd)
            os.rename(stemp_path, out_path)
        except Exception:
            print(f"{in_path.name} was not encrypted.")
            exit(-1)
        else:
            print(f"Passphrase: {passphrase}")
            print(f"{in_path.name} encrypted as {out_path.name}")
    else:
        try:
            passphrase = getpass("Passphrase: ")
            xc.decrypt(passphrase.encode('utf-8'))
        except Exception:
            print(f"{in_path.name} was not decrypted.")
            exit(-1)
        else:
            print(f"{in_path.name} decrypted as {in_path.stem}")


if __name__ == "__main__":
    XC_SUFFIX = '.xc'
    main()
