from mnemonic import Mnemonic
from web3 import Web3
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Crypto_Wallet:

    DEFAULT_FILE_NAME = 'wallet.json'
    PROVIDER_URL = "https://mainnet.infura.io/v3/9c6f33d4175a496c8a4f1b089cddefcc"

    def __init__(self, language="english"):
        self.mnemo = Mnemonic(language)
        self.w3 = Web3(Web3.HTTPProvider(self.PROVIDER_URL))
        self.account = None
        self.words = None 

    def create_wallet(self, strength=256, passphrase="", filename=DEFAULT_FILE_NAME):
        self.words = self.mnemo.generate(strength=strength)
        seed = self.mnemo.to_seed(self.words, passphrase)
        self.account = self.w3.eth.account.create(seed)
        self.save_wallet_to_file(filename)
        print('address:', self.account.address)
        print('private_key:', self.w3.to_hex(self.account.key))
        print('mnemonic:', self.words)

    @staticmethod
    def get_fernet_key(password: str) -> bytes:
        # Derive a key from the password
        salt = b"you_can_have_static_salt"  # Or generate and store separately
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256,
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_data(data: str, password: str) -> bytes:
        key = Crypto_Wallet.get_fernet_key(password)
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str) -> str:
        key = Crypto_Wallet.get_fernet_key(password)
        cipher_suite = Fernet(key)
        decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data

    def save_wallet_to_file(self, filename):
        if not self.account or not self.words:
            raise ValueError("No account or mnemonic words loaded or created.")
        data = {
            'address': self.account.address,
            'private_key': self.w3.to_hex(self.account.key),
            'mnemonic': self.words
        }
        password = input("Enter a password to encrypt the wallet file: ")
        encrypted_data = self.encrypt_data(json.dumps(data), password)
        with open(filename, 'wb') as file:
            file.write(encrypted_data)

    def load_wallet_from_file(self, filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File '{filename}' not found!")
        password = input("Enter the password to decrypt the wallet file: ")
        with open(filename, 'rb') as file:
            encrypted_data = file.read()
            try:
                data_str = self.decrypt_data(encrypted_data, password)
            except Exception:
                print("Incorrect password or corrupted file.")
                return
            data = json.loads(data_str)
            self.account = self.w3.eth.account.from_key(data['private_key'])
            self.words = data['mnemonic']

    def get_balance(self):
        if not self.account:
            print("No account loaded or created.")
            return 
        return self.w3.eth.get_balance(self.account.address)

    def get_address(self):
        if not self.account:
            print("No account loaded or created.")
            return
        return self.account.address


    def transfer_eth(self, receiver_address):
        if not self.account:
            raise ValueError("No account loaded or created.")
        
        print("Sender Account", self.account.address)
        
        sender_balance_wei = self.get_balance()
        sender_balance_eth = self.w3.from_wei(sender_balance_wei, 'ether')
        print(f"Sender's ETH Balance: {sender_balance_eth} ETH")
        
        amount_eth = float(input("Enter the amount of ETH to send: "))
        
        if amount_eth <= sender_balance_eth:
            amount_in_wei = self.w3.to_wei(amount_eth, 'ether')
            
            transaction = {
                'to': receiver_address,
                'value': amount_in_wei,
                'gas': 21000,
                'gasPrice': self.w3.to_wei('5', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
            }
            
            signed_transaction = self.w3.eth.account.sign_transaction(transaction, self.account.key)
            transaction_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
            
            print(f"Transaction Hash: {transaction_hash.hex()}")
        else:
            print("Insufficient balance.")

#Example:
#wallet = Crypto_Wallet()
#wallet.create_wallet()

#Example:
#wallet = Crypto_Wallet()
#wallet.load_wallet_from_file('wallet_info.json')
#print(wallet.get_address())
