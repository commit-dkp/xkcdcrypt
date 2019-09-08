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


class Xkcdcrypt:
    def __init__(self: object, inPath: str) -> None:
        self.SALT_SIZE = 16  # Size of salt in bytes
        self.NONCE_SIZE = 16  # Size of nonce in bytes
        self.inPath = inPath

    def encrypt(self: object) -> [bytes, str]:
        passphrase = self._genXkcdPhrase()
        salt = os.urandom(self.SALT_SIZE)
        key = self._deriveKey(passphrase.encode('utf-8'), salt)
        siv = SIV(key)
        nonce = os.urandom(self.NONCE_SIZE)
        ciphertext = salt + nonce + siv.seal(self._archive(), [nonce])
        return ciphertext, passphrase

    def _genXkcdPhrase(self: object) -> str:
        with open('words.txt', 'r') as wordFile:
            wordlist = wordFile.read()
        wordlist = wordlist.split()
        xkcdphrase = [choice(wordlist)
                      for word in range(4)]  # Words in passphrase
        return '-'.join(xkcdphrase)

    def _deriveKey(self: object, passphrase: bytes, salt: bytes) -> bytes:
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
            with tarfile.open(fileobj=buffer, mode='x:bz2') as arcFile:
                arcFile.add(self.inPath)
            buffer.seek(0)
            return buffer.read()

    def decrypt(self: object, passphrase: bytes) -> None:
        with open(self.inPath, 'rb') as inFile:
            salt = inFile.read(self.SALT_SIZE)
            key = self._deriveKey(passphrase, salt)
            siv = SIV(key)
            nonce = inFile.read(self.NONCE_SIZE)
            plaintext = siv.open(inFile.read(), [nonce])
        self._extract(plaintext)

    def _extract(self: object, plaintext: bytes) -> None:
        dest = (self.inPath.parent).joinpath(self.inPath.stem)
        with TemporaryDirectory() as tempDir:
            with BytesIO(plaintext) as buffer:
                with tarfile.open(fileobj=buffer, mode='r:bz2') as arcFile:
                    arcFile.extractall(tempDir)
            temp = Path(tempDir).joinpath(dest.name)
            os.rename(temp, dest)


def main() -> None:
    parser = argparse.ArgumentParser(description='Encrypt & decrypt files.')
    parser.add_argument('file', help='The file to be encrypted or decrypted.')
    inPath = Path(parser.parse_args().file)
    xc = Xkcdcrypt(inPath)
    if xcSuffix != inPath.suffix:
        try:
            ciphertext, passphrase = xc.encrypt()
            outPath = inPath.with_suffix(inPath.suffix + xcSuffix)
            stempFD, stempPath = mkstemp()
            os.write(stempFD, ciphertext)
            os.fsync(stempFD)
            os.close(stempFD)
            os.rename(stempPath, outPath)
        except:
            print(f"{inPath.name} was not encrypted.")
            exit(-1)
        else:
            print(f"Passphrase: {passphrase}")
            print(f"{inPath.name} encrypted as {outPath.name}")
    else:
        try:
            passphrase = getpass("Passphrase: ")
            xc.decrypt(passphrase.encode('utf-8'))
        except:
            print(f"{inPath.name} was not decrypted.")
            exit(-1)
        else:
            print(f"{inPath.name} decrypted as {inPath.stem}")


if __name__ == "__main__":
    xcSuffix = '.xc'
    main()
