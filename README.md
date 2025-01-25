# Le Chiffre Indéchiffrable.

> [!WARNING]
> Do not use it for anything serious. 

This is a simple implementation of the Vigenère cipher. The Vigenère cipher
is a method of encrypting alphabetic text by using a simple form of
polyalphabetic substitution. A polyalphabetic cipher uses multiple
substitution alphabets to encrypt the data. The Vigenère cipher has been
reinvented many times. The method is named after Blaise de Vigenère, though
it was actually first described by Giovan Battista Bellaso in 1553.

The Vigenère cipher is essentially a Caesar cipher with a different shift
for each letter. To encrypt, a table of alphabets can be used, termed a
tabula recta, Vigenère square, or Vigenère table. It consists of the
alphabet written out 26 times in different rows, each alphabet shifted
cyclically to the left compared to the previous alphabet, corresponding to
the 26 possible Caesar ciphers. At different points in the encryption
process, the cipher uses a different alphabet from one of the rows. The
alphabet used at each point depends on a repeating keyword.

# Examples

The Viégère cipher key is a word, such as "lemon". Each letter of the key
is a shift value. In this case, the key is "lemon", which translates to
[11, 4, 12, 14, 13]. The key is repeated for the length of the plaintext.
The plaintext "attackatdawn" is encrypted as follows:

```rust
use vgnr::Vigenere;

let scheme = Vigenere::new("lemon");
let plaintext = "attackatdawn";

let ciphertext = scheme.encrypt(plaintext).unwrap();
assert_eq!(ciphertext, "lxfopvefrnhr");

let decrypted = scheme.decrypt(&ciphertext).unwrap();
assert_eq!(decrypted, plaintext);

```

The Caesar cipher is a special case of the Vigenère cipher where the key is
a single letter. The Caesar cipher is a type of substitution cipher in which
each letter in the plaintext is shifted a certain number of places down the
alphabet.

```rust
use vgnr::Vigenere;

let scheme = Vigenere::new("d");
let plaintext = "attackatdawn";

let ciphertext = scheme.encrypt(plaintext).unwrap();
assert_eq!(ciphertext, "dwwdfndwdqgq");

let decrypted = scheme.decrypt(&ciphertext).unwrap();
assert_eq!(decrypted, plaintext);
```

The Vigenère cipher is simple to understand and implement. Please,
do not use this for anything serious. That's a cipher invented
in the 16th century. It's not secure.

Cryptanalysis of the Vigenère cipher is possible. The primary weakness of
the Vigenère cipher is the repeating nature of its key. If a cryptanalyst
correctly guesses the key's length, the cipher text can be broken by
determining the shift value for each letter in the key.


The Kasiski examination, also called the Kasiski test, is a cryptanalytic
method that breaks Vigenère ciphers. The Kasiski examination takes advantage
of the fact that repeated words are, by chance, sometimes encrypted using the 
same key letters, leading to repeated groups in the ciphertext. For example, 
consider the following encryption using the keyword ABCD:

```
Key:        ABCDABCDABCDABCDABCDABCDABCD
Plaintext:  cryptoisshortforcryptography
Ciphertext: CSASTPKVSIQUTGQUCSASTPIUAQJB
```

The repeated groups in the ciphertext are "CSASTP" and "CSASTP". The distance
between the two groups is 12 characters. The distance between the two groups
is a multiple of the key length. In this case, the key length is 4. 

See more about breaking the Vigenère cipher in the [Wiki](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).

Use this crate as a challenge to learn more about cryptography and
try to break the Vigenère cipher. It's a fun exercise.
