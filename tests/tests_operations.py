import pytest
from Crypto.PublicKey import RSA

from rsa import decrypt, encrypt, generate_key


def test_key_generation():
    # Test if generate_key returns an RSA key
    seed = "test_seed"
    key = generate_key(seed)
    assert isinstance(key, RSA.RsaKey)
    assert key.size_in_bits() == 2048  # Verify key length


def test_encrypt_decrypt():
    # Generate a key pair
    seed = "test_seed"
    private_key = generate_key(seed)
    public_key = private_key.publickey().exportKey()

    # Encrypt and decrypt a message
    message = "Hello, world!"
    encrypted_message = encrypt(message, public_key, encoded=False)
    decrypted_message = decrypt(encrypted_message, private_key.exportKey())

    # Decode decrypted message back to string if necessary
    assert decrypted_message.decode() == message


def test_decrypt_invalid_key():
    # Generate two different key pairs
    seed1 = "test_seed1"
    seed2 = "test_seed2"
    private_key1 = generate_key(seed1)
    private_key2 = generate_key(seed2)
    public_key1 = private_key1.publickey().exportKey()

    # Encrypt a message with the first public key
    message = "Hello, world!"
    encrypted_message = encrypt(message, public_key1, encoded=False)

    # Try to decrypt with a different private key
    decrypted_message = decrypt(encrypted_message, private_key2.exportKey())
    assert decrypted_message is None


def test_encrypt_encoded_flag():
    # Generate a key pair
    seed = "test_seed"
    private_key = generate_key(seed)
    public_key = private_key.publickey().exportKey()

    # Encrypt with encoded=True, meaning the message should already be bytes
    message = b"Hello, encoded world!"
    encrypted_message = encrypt(message, public_key, encoded=True)
    decrypted_message = decrypt(encrypted_message, private_key.exportKey())

    # Verify the decrypted message matches the original
    assert decrypted_message == message


def test_backwards_compatibility():
    # Generate a private key
    seed = "test_seed"
    private_key = generate_key(seed)

    # Test that generate_key method returns the same results
    message = "Hello, world!"
    encrypted_message = (
        b"GD3PRYKF41iltorHt7IXkGNYRzDV+g/lTYQIekZWrUu/fDBuGY"
        b"kRBamlQz0KSj84azlsBwbdz2AVfb169ox4B6HN8AYTIxAqXxQP"
        b"59PMjA7ViDbSuWVTdlQbeGkk8JArsx11QS+xJR9dgNlXd522iY"
        b"IzmdSsJ29zZ0iu5AHOE7UwDjS0RCliP0vNCMCS1AileNX3udCZ"
        b"oRExqy7aG62SCHRjT/m5CcQnRs4zdtCF7y5lPcxXZAyx8WmsFC"
        b"HSIXMymB+R60sga+SWgS4erLDArQQIAZisxbRE6skozCMxJF/z"
        b"c20jY0dYCKBjwK0ps2ustc6FM9qmsLlPHeY2a8tpNg=="
    )

    decrypted_message = decrypt(encrypted_message, private_key.exportKey())

    # Decode decrypted message back to string if necessary
    assert decrypted_message.decode() == message
