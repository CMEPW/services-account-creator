import argparse
import requests
import base64
import math
from enum import IntEnum
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0'
EMAIL_DOMAIN = 'smersh.lan'

CODIMD_URL = 'http://codimd.smersh.lan/'
BITWARDEN_URL = 'http://bitwarden.smersh.lan/'

KDF_ITERATIONS = 100000


class BitwardenEncType(IntEnum):

    AESCBC256_B64 = 0
    AESCBC128_HMACSHA256_B64 = 1
    AESCBC256_HMACSHA256_B64 = 2
    RSA2048_OAEPSHA256_B64 = 3
    RSA2048_OAEPSHA1_B64 = 4
    RSA2048_OAEPSHA256_HMACHSA256_B64 = 5
    RSA2048_OAEPSHA1_HMACSHA256_B64 = 6


class BitwardenSymmetricCryptoKey:

    def __init__(self, key):
        keylen = len(key)
        assert((keylen % 2) == 0)

        self.key = key
        self.enc_key = key[:keylen // 2]
        self.mac_key = key[keylen // 2:]


class BitwardenCrypto:

    def __init__(self, username, email, password, kdf_iterations=KDF_ITERATIONS):
        self.username = username.lower()
        self.email = email.lower()
        self.password = password
        self.kdf_iterations = kdf_iterations

        self._make_master_key()
        self._make_rsa_keypair()
        self._make_symmetric_key()


    def _make_master_key(self):
        self.master_key = PBKDF2(
            self.password,
            self.email,
            dkLen=32,
            count=self.kdf_iterations,
            hmac_hash_module=SHA256
        )

        self._make_master_key_hash()
        self._make_stretched_master_key()


    def _make_master_key_hash(self):
        self.master_key_hash = PBKDF2(
            self.master_key,
            self.password,
            dkLen=32,
            count=1,
            hmac_hash_module=SHA256
        )


    def _make_stretched_master_key(self):
        enc_key = self.hkdf_expand(self.master_key, b'enc', 32)
        mac_key = self.hkdf_expand(self.master_key, b'mac', 32)

        self.stretched_master_key = BitwardenSymmetricCryptoKey(enc_key + mac_key)


    def _make_rsa_keypair(self):
        self.private_key = RSA.generate(2048, e=65537)
        self.public_key = RSA.construct((self.private_key.n, self.private_key.e))


    def _make_symmetric_key(self):
        self.symmetric_key = BitwardenSymmetricCryptoKey(get_random_bytes(64))


    @staticmethod
    def encrypt(data, enc_key, mac_key = None):
        enc_type = BitwardenEncType.AESCBC256_B64
        iv = get_random_bytes(16)
        aes = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        ct = aes.encrypt(pad(data, AES.block_size))

        if mac_key is not None:
            enc_type = BitwardenEncType.AESCBC256_HMACSHA256_B64
            hmac = HMAC.new(mac_key, digestmod=SHA256)

            hmac.update(iv + ct)

            return '{}.{}|{}|{}'.format(
                enc_type,
                base64.b64encode(iv).decode('utf8'),
                base64.b64encode(ct).decode('utf8'),
                base64.b64encode(hmac.digest()).decode('utf8')
            )

        return '{}.{}|{}'.format(
            enc_type,
            base64.b64encode(iv).decode('utf8'),
            base64.b64encode(ct).decode('utf8')
        )


    @staticmethod
    def hkdf_expand(key, info, size):
        okm = b''
        previous_t = b''

        for i in range(0, math.ceil(size / 32)):
            hmac = HMAC.new(key, digestmod=SHA256)
            t = previous_t + info + bytes([i + 1])

            hmac.update(t)
            previous_t = hmac.digest()

            okm += previous_t

        return okm


    @property
    def b64_master_key_hash(self):
        return base64.b64encode(self.master_key_hash).decode('utf8')


    @property
    def pem_public_key(self):
        return base64.b64encode(self.public_key.export_key(format='DER')).decode('utf8')


    @property
    def ciphered_private_key(self):
        return self.encrypt(
            self.private_key.export_key(format='DER'),
            self.symmetric_key.enc_key,
            self.symmetric_key.mac_key
        )


    @property
    def ciphered_symmetric_key(self):
        return self.encrypt(
            self.symmetric_key.key,
            self.stretched_master_key.enc_key,
            self.stretched_master_key.mac_key
        )


def email_from_username(username):
    return username + '@' + EMAIL_DOMAIN


def concatenate_path(domain, path):
    if domain[-1] == '/':
        domain = domain[:-1]

    if path[0] != '/':
        path = '/' + path

    return domain + path


def create_codimd_account(url, username, password):
    email = email_from_username(username)
    response = requests.post(concatenate_path(url, '/register'), headers={
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': USER_AGENT
    }, data={
        'email': email,
        'password': password
    })

    return response.status_code == 200


def create_bitwarden_account(url, username, password):
    email = email_from_username(username)
    crypto = BitwardenCrypto(username, email, password)

    headers = {
        'Content-Type': 'application/json'
    }

    data = {
        'email': email,
        'kdf': 0,
        'kdfIterations': KDF_ITERATIONS,
        'key': crypto.ciphered_symmetric_key,
        'keys': {
            'encryptedPrivateKey': crypto.ciphered_private_key,
            'publicKey': crypto.pem_public_key
        },
        'masterPasswordHash': crypto.b64_master_key_hash,
        'masterPasswordHint': None,
        'name': username
    }

    response = requests.post(
        concatenate_path(url, '/api/accounts/register'),
        headers=headers,
        json=data
    )

    return response.status_code == 200


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('username', type=str, help='The username of the account to be created (the domain will be automatically appended for the email)')
    parser.add_argument('password', type=str, help='The password of the account to be created')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    username = args.username.lower()

    if create_codimd_account(CODIMD_URL, username, args.password):
        print('CodiMD account successfully created')
    else:
        print('Unable to create the CodiMD account')

    if create_bitwarden_account(BITWARDEN_URL, username, args.password):
        print('Bitwarden account successfully created')
    else:
        print('Unable to create the Bitwarden account')