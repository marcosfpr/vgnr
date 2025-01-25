//! Le Chiffre Indéchiffrable.
//!
//! This is a simple implementation of the Vigenère cipher. The Vigenère cipher
//! is a method of encrypting alphabetic text by using a simple form of
//! polyalphabetic substitution. A polyalphabetic cipher uses multiple
//! substitution alphabets to encrypt the data. The Vigenère cipher has been
//! reinvented many times. The method is named after Blaise de Vigenère, though
//! it was actually first described by Giovan Battista Bellaso in 1553.
//!
//! The Vigenère cipher is essentially a Caesar cipher with a different shift
//! for each letter. To encrypt, a table of alphabets can be used, termed a
//! tabula recta, Vigenère square, or Vigenère table. It consists of the
//! alphabet written out 26 times in different rows, each alphabet shifted
//! cyclically to the left compared to the previous alphabet, corresponding to
//! the 26 possible Caesar ciphers. At different points in the encryption
//! process, the cipher uses a different alphabet from one of the rows. The
//! alphabet used at each point depends on a repeating keyword.
//!
//! # Examples
//!
//! The Viégère cipher key is a word, such as "lemon". Each letter of the key
//! is a shift value. In this case, the key is "lemon", which translates to
//! [11, 4, 12, 14, 13]. The key is repeated for the length of the plaintext.
//! The plaintext "attackatdawn" is encrypted as follows:
//!
//! ```no_run
//! use vgnr::Vigenere;
//!
//! let scheme = Vigenere::new("lemon");
//! let plaintext = "attackatdawn";
//!
//! let ciphertext = scheme.encrypt(plaintext).unwrap();
//! assert_eq!(ciphertext, "lxfopvefrnhr");
//!
//! let decrypted = scheme.decrypt(&ciphertext).unwrap();
//! assert_eq!(decrypted, plaintext);
//!
//! ```
//!
//! The Caesar cipher is a special case of the Vigenère cipher where the key is
//! a single letter. The Caesar cipher is a type of substitution cipher in which
//! each letter in the plaintext is shifted a certain number of places down the
//! alphabet.
//!
//! ```no_run
//! use vgnr::Vigenere;
//!
//! let scheme = Vigenere::new("d");
//! let plaintext = "attackatdawn";
//!
//! let ciphertext = scheme.encrypt(plaintext).unwrap();
//! assert_eq!(ciphertext, "dwwdfndwdqgq");
//!
//! let decrypted = scheme.decrypt(&ciphertext).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```
//!
//! The Vigenère cipher is simple to understand and implement. Please,
//! do not use this for anything serious. That's a cipher invented
//! in the 16th century. It's not secure.
//!
//! Cryptanalysis of the Vigenère cipher is possible. The primary weakness of
//! the Vigenère cipher is the repeating nature of its key. If a cryptanalyst
//! correctly guesses the key's length, the cipher text can be broken by
//! determining the shift value for each letter in the key.
//!
//! 
//! The Kasiski examination, also called the Kasiski test, is a cryptanalytic
//! method that breaks Vigenère ciphers. The Kasiski examination takes advantage
//! of the fact that repeated words are, by chance, sometimes encrypted using the 
//! same key letters, leading to repeated groups in the ciphertext. For example, 
//! consider the following encryption using the keyword ABCD:
//!
//! Key:        ABCDABCDABCDABCDABCDABCDABCD
//! Plaintext:  cryptoisshortforcryptography
//! Ciphertext: CSASTPKVSIQUTGQUCSASTPIUAQJB
//!
//! The repeated groups in the ciphertext are "CSASTP" and "CSASTP". The distance
//! between the two groups is 12 characters. The distance between the two groups
//! is a multiple of the key length. In this case, the key length is 4. 
//!
//! See more about breaking the Vigenère cipher in the Wiki page:
//! https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher
//!
//! Use this crate as a challenge to learn more about cryptography and
//! try to break the Vigenère cipher. It's a fun exercise.

/// The Vigenère alphabet length.
const ALPHABET_LEN: usize = 26;

/// The Vigenère alphabet.
const ALPHABET: [char; ALPHABET_LEN] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];

/// The Vigenère cipher scheme.
pub struct Vigenere<const N: usize> {
    /// The Vigenère alphabet.
    alphabet: [char; N],
    /// The Vigenère matrix.
    matrix: [[char; N]; N],
    /// The Vigenère key.
    key: String,
}

impl Vigenere<ALPHABET_LEN> {
    /// Create a new Vigenère cipher scheme with a given key.
    ///
    /// # Arguments
    /// * `key` - The Vigenère key.
    ///
    /// # Returns
    /// A new Vigenère cipher scheme.
    pub fn new(key: &str) -> Self {
        Self::with_alphabet(key, ALPHABET)
    }
}

impl<const N: usize> Vigenere<N> {
    /// Create a new Vigenère cipher scheme for a specific alphabet.
    ///
    /// # Arguments
    /// * `key` - The Vigenère key.
    /// * `alphabet` - The Vigenère alphabet.
    ///
    /// # Returns
    /// A new Vigenère cipher scheme.
    pub fn with_alphabet(key: &str, alphabet: [char; N]) -> Self {
        let matrix = Self::matrix(alphabet);
        Self {
            alphabet,
            matrix,
            key: key.to_string(),
        }
    }

    /// Encrypt a plaintext message using the Vigenère cipher.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext message.
    ///
    /// # Returns
    /// The encrypted message.
    ///
    /// # Panics
    /// If the plaintext message contains characters that are not in the
    /// Vigenère alphabet.
    pub fn encrypt(&self, plaintext: impl Into<String>) -> String {
        let plaintext = plaintext.into();
        let padded_key = self.pad_key(&plaintext);
        let mut ciphertext = String::with_capacity(plaintext.len());
        for (p, k) in plaintext.chars().zip(padded_key.chars()) {
            let row = self
                .alphabet
                .iter()
                .position(|&c| c == k)
                .expect("The key contains characters that are not in the Vigenère alphabet.");
            let col =
                self.alphabet.iter().position(|&c| c == p).expect(
                    "The plaintext contains characters that are not in the Vigenère alphabet.",
                );
            ciphertext.push(self.matrix[row][col]);
        }
        ciphertext
    }

    /// Decrypt a ciphertext message using the Vigenère cipher.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext message.
    ///
    /// # Returns
    /// The decrypted message.
    ///
    /// # Panics
    /// If the ciphertext message contains characters that are not in the
    /// Vigenère alphabet.
    pub fn decrypt(&self, ciphertext: impl Into<String>) -> String {
        let ciphertext = ciphertext.into();
        let padded_key = self.pad_key(&ciphertext);
        let mut plaintext = String::with_capacity(ciphertext.len());
        for (c, k) in ciphertext.chars().zip(padded_key.chars()) {
            let row = self
                .alphabet
                .iter()
                .position(|&c| c == k)
                .expect("The key contains characters that are not in the Vigenère alphabet.");
            let col = self.matrix[row].iter().position(|&x| x == c).expect(
                "The ciphertext contains characters that are not in the Vigenère alphabet.",
            );
            plaintext.push(self.alphabet[col]);
        }
        plaintext
    }

    /// Pads the key to the length of the message.
    ///
    /// # Arguments
    /// * `message` - The message.
    ///
    /// # Returns
    /// The padded key.
    ///
    /// # Example
    /// Let the key be "lemon" and the message be "attackatdawn". The padded key
    /// is "lemonlemonle".
    fn pad_key(&self, message: &str) -> String {
        let key_len = self.key.len();
        let message_len = message.len();
        let mut padded_key = String::with_capacity(message_len);
        for i in 0..message_len {
            padded_key.push(self.key.chars().nth(i % key_len).unwrap());
        }
        padded_key
    }

    /// Create the Vigenère matrix. The matrix is a table of alphabets used in
    /// the encryption process. Each row of the table is derived from the
    /// alphabet by shifting the letters to the left by one position.
    ///
    /// The first row is the alphabet itself. The second row is the alphabet
    /// shifted by one position. The third row is the alphabet shifted by two
    /// positions, and so on.
    ///
    /// We don't assume the characters are ordered in the ASCII table. That means
    /// you can specify any alphabet at any order, including with repeated numbers.
    ///
    /// # Arguments
    /// * `alphabet` - The Vigenère alphabet.
    ///
    /// # Returns
    /// The Vigenère matrix.
    #[inline]
    fn matrix(alphabet: [char; N]) -> [[char; N]; N] {
        let mut matrix = [['A'; N]; N];
        for i in 0..N {
            for j in 0..N {
                matrix[i][j] = alphabet[(i + j) % N];
            }
        }
        matrix
    }
}

#[cfg(test)]
impl<const N: usize> Vigenere<N> {
    /// Get the Vigenère matrix.
    pub fn get_matrix(&self) -> &[[char; N]; N] {
        &self.matrix
    }
}

#[cfg(test)]
mod tests {
    use crate::{Vigenere, ALPHABET};

    #[test]
    fn test_vigenere_matrix() {
        let vigenere = Vigenere::new("lemon");
        let matrix = vigenere.get_matrix();
        assert_eq!(matrix[0], ALPHABET);
    }

    #[test]
    fn test_vigenere_matrix_custom_alphabet() {
        let vigenere = Vigenere::with_alphabet("lemon", ['C', 'A', 'E', 'S', 'A', 'R']);
        let matrix = vigenere.get_matrix();
        assert_eq!(matrix[0], ['C', 'A', 'E', 'S', 'A', 'R']);
        assert_eq!(matrix[1], ['A', 'E', 'S', 'A', 'R', 'C']);
        assert_eq!(matrix[2], ['E', 'S', 'A', 'R', 'C', 'A']);
        assert_eq!(matrix[3], ['S', 'A', 'R', 'C', 'A', 'E']);
        assert_eq!(matrix[4], ['A', 'R', 'C', 'A', 'E', 'S']);
        assert_eq!(matrix[5], ['R', 'C', 'A', 'E', 'S', 'A']);
    }

    #[test]
    fn test_vigenere_matrix_custom_alphabet_lowercase() {
        let vigenere = Vigenere::with_alphabet("lemon", ['c', 'a', 'e', 's', 'a', 'r']);
        let matrix = vigenere.get_matrix();
        assert_eq!(matrix[0], ['c', 'a', 'e', 's', 'a', 'r']);
        assert_eq!(matrix[1], ['a', 'e', 's', 'a', 'r', 'c']);
        assert_eq!(matrix[2], ['e', 's', 'a', 'r', 'c', 'a']);
        assert_eq!(matrix[3], ['s', 'a', 'r', 'c', 'a', 'e']);
        assert_eq!(matrix[4], ['a', 'r', 'c', 'a', 'e', 's']);
        assert_eq!(matrix[5], ['r', 'c', 'a', 'e', 's', 'a']);
    }

    #[test]
    fn test_vigenere_encrypt() {
        let vigenere = Vigenere::new("lemon");
        let plaintext = "attackatdawn";
        let ciphertext = vigenere.encrypt(plaintext);
        assert_eq!(ciphertext, "lxfopvefrnhr");
    }

    #[test]
    fn test_vigenere_decrypt() {
        let vigenere = Vigenere::new("lemon");
        let ciphertext = "lxfopvefrnhr";
        let plaintext = vigenere.decrypt(ciphertext);
        assert_eq!(plaintext, "attackatdawn");
    }
}
