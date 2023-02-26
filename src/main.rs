use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{AeadCore, Aes256GcmSiv, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{PasswordHash, PasswordHashString, PasswordHasher, SaltString};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::{env, fs, io};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;

const WORDS_LEN: usize = 4;
const XC_SUFFIX: &str = ".xc";

fn unpack(tarball: &[u8], in_path: &str) -> Result<String, Box<dyn Error>> {
    let temp_dir = tempfile::tempdir()?;
    let mut archive = Archive::new(tarball);
    archive.unpack(&temp_dir)?;
    let parent = match Path::new(in_path).parent() {
        Some(parent) => parent,
        None => Err("No parent!")?,
    };
    for entry in fs::read_dir(&temp_dir)? {
        let entry = entry?;
        let dest = [parent, Path::new(&entry.file_name())]
            .iter()
            .collect::<PathBuf>();
        fs::rename(entry.path(), dest)?;
    }
    let out_path = match in_path.strip_suffix(XC_SUFFIX) {
        Some(out_path) => out_path.to_owned(),
        None => Err("No suffix!")?,
    };
    Ok(out_path)
}

fn decrypt(phc: &PasswordHashString, ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = match phc.hash() {
        Some(key) => key,
        None => Err("No key!")?,
    };
    let cipher = match Aes256GcmSiv::new_from_slice(key.as_bytes()) {
        Ok(cipher) => cipher,
        Err(_err) => Err("Invalid key length!")?,
    };
    let nonce_len = Nonce::default().len();
    let nonce = Nonce::from_slice(&ciphertext[0..nonce_len]);
    let plaintext = match cipher.decrypt(nonce, &ciphertext[nonce_len..]) {
        Ok(plaintext) => plaintext,
        Err(_err) => Err("AES decrypt error!")?,
    };
    Ok(plaintext)
}

fn read_in(in_path: &str) -> Result<(String, Vec<u8>), Box<dyn Error>> {
    let file = File::open(in_path)?;
    let mut buf_reader = BufReader::new(file);
    let mut phc_len = 0_u8;
    buf_reader.read_exact(std::slice::from_mut(&mut phc_len))?;
    let mut phc = vec![0_u8; usize::from(phc_len)];
    buf_reader.read_exact(&mut phc)?;
    let phc = String::from_utf8(phc)?;
    let mut ciphertext = Vec::new();
    buf_reader.read_to_end(&mut ciphertext)?;
    Ok((phc, ciphertext))
}

fn prompt_phrase() -> Result<String, Box<dyn Error>> {
    let mut passphrase = String::new();
    print!("Passphrase: ");
    io::stdout().flush()?;
    io::stdin().read_line(&mut passphrase)?;
    passphrase.truncate(passphrase.trim_end().len());
    Ok(passphrase)
}

fn write_out(
    password_hash: &PasswordHashString,
    ciphertext: &[u8],
    in_path: &str,
) -> Result<String, Box<dyn Error>> {
    let mut temp_file = NamedTempFile::new()?;
    let key = match password_hash.hash() {
        Some(key) => key,
        None => Err("No key!")?,
    };
    let mut phc = match password_hash.as_str().strip_suffix(&key.to_string()) {
        Some(phc) => phc,
        None => Err("No key at end!")?,
    };
    phc = match phc.strip_suffix("$") {
        Some(phc) => phc,
        None => Err("No \"$\" at end!")?,
    };
    let phc_len = u8::try_from(phc.len())?;
    temp_file.write_all(std::slice::from_ref(&phc_len))?;
    temp_file.write_all(phc.as_bytes())?;
    temp_file.write_all(ciphertext)?;
    let out_path = in_path.to_owned() + XC_SUFFIX;
    fs::rename(temp_file.path(), &out_path)?;
    Ok(out_path)
}

fn encrypt(password_hash: &PasswordHashString, tarball: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = match password_hash.hash() {
        Some(key) => key,
        None => Err("No key!")?,
    };
    let cipher = match Aes256GcmSiv::new_from_slice(key.as_bytes()) {
        Ok(cipher) => cipher,
        Err(_err) => Err("Invalid key length!")?,
    };
    let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);
    let ciphertext = match cipher.encrypt(&nonce, tarball) {
        Ok(ciphertext) => ciphertext,
        Err(_err) => Err("AES encrypt error!")?,
    };
    let ciphertext = [nonce.as_slice(), &ciphertext].concat();
    Ok(ciphertext)
}

fn archive(in_path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = Builder::new(Vec::new());
    if Path::new(in_path).is_dir() {
        builder.append_dir_all(in_path, in_path)?;
    } else {
        let mut file = File::open(in_path)?;
        builder.append_file(in_path, &mut file)?;
    }
    let builder = builder.into_inner()?;
    Ok(builder)
}

fn restore_phc(phc: &str) -> Result<(Argon2, SaltString), Box<dyn Error>> {
    let password_hash = match PasswordHash::new(phc) {
        Ok(password_hash) => password_hash,
        Err(_err) => Err("PHC error!")?,
    };
    let algorithm = match Algorithm::try_from(password_hash.algorithm) {
        Ok(algorithm) => algorithm,
        Err(_err) => Err("Invalid algorithm!")?,
    };
    let version = match password_hash.version {
        Some(version) => match Version::try_from(version) {
            Ok(version) => version,
            Err(_err) => Err("Invalid version!")?,
        },
        None => Err("No version!")?,
    };
    let params = match Params::try_from(&password_hash) {
        Ok(params) => params,
        Err(_err) => Err("Params error!")?,
    };
    let argon2 = Argon2::new(algorithm, version, params);
    let salt = match password_hash.salt {
        Some(salt) => match SaltString::new(salt.as_str()) {
            Ok(salt) => salt,
            Err(_err) => Err("Salt error!")?,
        },
        None => Err("No salt!")?,
    };
    Ok((argon2, salt))
}

fn derive_key(passphrase: &str, phc: Option<&str>) -> Result<PasswordHashString, Box<dyn Error>> {
    let (argon2, salt) = match phc {
        Some(phc) => restore_phc(phc)?,
        None => (Argon2::default(), SaltString::generate(&mut OsRng)),
    };
    let password_hash = match argon2.hash_password(passphrase.as_bytes(), &salt) {
        Ok(password_hash) => password_hash.serialize(),
        Err(_err) => Err("Argon2 error!")?,
    };
    Ok(password_hash)
}

fn xkcd_phrase() -> Result<String, Box<dyn Error>> {
    let file = File::open("words.txt")?;
    let buf_reader = BufReader::new(file);
    let mut words = Vec::new();
    for line in buf_reader.lines() {
        let line = line?;
        words.push(line);
    }
    let mut phrase_words = [""; WORDS_LEN];
    for index in 0..WORDS_LEN {
        match words.choose(&mut OsRng) {
            Some(word) => phrase_words[index] = word,
            None => Err("Words empty!")?,
        };
    }
    let passphrase = phrase_words.join("-");
    println!("Passphrase: {passphrase}");
    Ok(passphrase)
}

fn validate_path() -> Result<String, Box<dyn Error>> {
    let mut args = env::args();
    if args.len() > 2 {
        Err("Too many arguments!")?
    }
    let in_path = match args.nth(1) {
        Some(in_path) => in_path,
        None => Err("No path!")?,
    };
    match Path::new(&in_path).try_exists() {
        Ok(true) => Ok(in_path),
        Ok(false) => Err("Broken symbolic link!")?,
        Err(err) => Err(err)?,
    }
}

fn run_app() -> Result<(), Box<dyn Error>> {
    let in_path = validate_path()?;
    if in_path.ends_with(XC_SUFFIX) == false {
        let passphrase = xkcd_phrase()?;
        let password_hash = derive_key(&passphrase, None)?;
        let tarball = archive(&in_path)?;
        let ciphertext = encrypt(&password_hash, &tarball)?;
        let out_path = write_out(&password_hash, &ciphertext, &in_path)?;
        println!("{in_path} encrypted as {out_path}");
    } else {
        let passphrase = prompt_phrase()?;
        let (phc, ciphertext) = read_in(&in_path)?;
        let password_hash = derive_key(&passphrase, Some(&phc))?;
        let tarball = decrypt(&password_hash, &ciphertext)?;
        let out_path = unpack(&tarball, &in_path)?;
        println!("{in_path} decrypted as {out_path}");
    }
    Ok(())
}

fn main() {
    std::process::exit(match run_app() {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("error: {err:?}");
            1
        }
    });
}
