import base64
from struct import pack

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA


def encrypt(message, public_key, encoded=False):
    rsa_key = RSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    if not encoded:
        message = str.encode(message)
    return base64.b64encode(cipher.encrypt(message))


def decrypt(encrypted_message, private_key):
    rsa_key = RSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    try:
        return cipher.decrypt(base64.b64decode(encrypted_message))
    except ValueError:
        return None


def generate_key(seed):
    # based on https://stackoverflow.com/questions/18264314/#answer-18266970
    seed_128 = HMAC.new(
        bytes(seed, "utf-8") + b"Application: 2nd key derivation"
    ).digest()

    class PRNG(object):

        def __init__(self, seed):
            self.index = 0
            self.seed = seed
            self.buffer = b""

        def __call__(self, n):
            while len(self.buffer) < n:
                self.buffer += HMAC.new(self.seed + pack("<I", self.index)).digest()
                self.index += 1
            result, self.buffer = self.buffer[:n], self.buffer[n:]
            return result

    return RSA.generate(2048, randfunc=PRNG(seed_128))
