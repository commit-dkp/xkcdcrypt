# **_For those of you who heed warnings: do not use this anywhere, ever._**

xkcdcrypt is a proof-of-concept file encryption tool. The concept it intends to demonstrate, in it's own small way, is that human-centered design results in higher-security implementations.

Credential stuffing, password spraying, and brute force are all principally mitigated by _not_ tasking users to choose the password from which the encryption key is derived. Instead, a [XKCD](https://xkcd.com/936/)-style passphrase is randomly generated, and printed to the terminal after the encrypted copy is created. You can read more about XKCD-style passphrases in [XKCD Explained](https://www.explainxkcd.com/wiki/index.php/936:_Password_Strength).

The XKCD-style passphrase and a cryptographically random 128-bit salt are fed to the [Argon2](https://github.com/P-H-C/phc-winner-argon2) key derivation function to derive a 256-bit key. Argon2 summarizes the state of the art in the design of password cracking resistance. You can read more about Argon2 in the [Password Hashing Competition](https://password-hashing.net).

The 256-bit key is used in [AES-SIV](https://web.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf) encryption and decryption operations. AES-SIV provides nonce reuse misuse resistance. You can read more about AES-SIV in the [miscreant encryption library](https://github.com/miscreant/miscreant/wiki/AES-SIV).

```
$ xkcdcrypt.py example.txt
Passphrase: correct-horse-battery-staple
example.txt encrypted as example.txt.xc

$ xkcdcrypt.py example.txt.xc
Passphrase: <correct-horse-battery-staple>
example.txt.xc decrypted as example.txt

$ xkcdcrypt.py example/
Passphrase: correct-horse-battery-staple
example encrypted as example.xc

$ xkcdcrypt.py example.xc
Passphrase: <correct-horse-battery-staple>
example.xc decrypted as example
