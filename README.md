# **_For those of you who heed warnings: do not use this anywhere, ever._**

xkcdcrypt is a proof-of-concept file encryption tool. The concept it intends to demonstrate, in its own small way, is
that human-centered design results in higher-security implementations.

Credential stuffing, password spraying, and brute force are all principally mitigated by _not_ tasking users to choose
the password from which the encryption key is derived. Instead, a [XKCD](https://xkcd.com/936/)-style passphrase is
randomly generated, and printed to the terminal. You can read more about XKCD-style passphrases in
[XKCD Explained](https://www.explainxkcd.com/wiki/index.php/936:_Password_Strength).

The XKCD-style passphrase and a cryptographically random 128-bit salt are fed to the
[Argon2](https://www.cryptolux.org/index.php/Argon2) key derivation function to derive a 256-bit key. Argon2 summarizes
the state of the art in the design of password cracking resistance. You can read more about Argon2 in the
[Rust Crypto crate](https://docs.rs/argon2/latest/argon2/).

The 256-bit key is used in [AES-GCM-SIV](https://cyber.biu.ac.il/aes-gcm-siv/) encryption and decryption operations.
AES-GCM-SIV provides nonce reuse misuse resistance. You can read more about AES-GCM-SIV in the
[Rust Crypto crate](https://docs.rs/aes-gcm-siv/latest/aes_gcm_siv/).

```text
$ xkcdcrypt example.txt
Passphrase: correct-horse-battery-staple
example.txt encrypted as example.txt.xc

$ xkcdcrypt example.txt.xc
Passphrase: <correct-horse-battery-staple>
example.txt.xc decrypted as example.txt

$ xkcdcrypt example/
Passphrase: correct-horse-battery-staple
example encrypted as example.xc

$ xkcdcrypt example.xc
Passphrase: <correct-horse-battery-staple>
example.xc decrypted as example
```
