# XChaCha20-Poly1305 - Differnt key per message increases security given ChaCha20-Poly1305 uses a 64 bit nonce that's prone to collision while sending many messages

This is a test/example of ChaCha20-Poly1305 ( https://download.libsodium.org/doc/secret-key_cryptography/aead.html ) using libSodium.

Additionally, it increases security by deriving a different key per message by using techniques from https://download.libsodium.org/doc/key_derivation/index.html#nonce-extension 



Cheers!
