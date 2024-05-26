import os
import hashlib
import base58
import ecdsa

def generate_private_key():
    """
    Generate a random 256-bit private key.

    Input:
        None

    Output:
        str: A 64-character hexadecimal string representing the private key.
    """
    return os.urandom(32).hex()

def private_to_public(private_key_hex):
    """
    Derive the public key from the given private key.

    Input:
        private_key_hex (str): A 64-character hexadecimal string representing the private key.

    Output:
        str: A 130-character hexadecimal string representing the uncompressed public key.
    """
    private_key_bytes = bytes.fromhex(private_key_hex)
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = '04' + key_bytes.hex()  # 0x04 denotes an uncompressed key
    return key_hex

def sha256(data_hex):
    """
    Compute the SHA-256 hash of the given data.

    Input:
        data_hex (str): A hexadecimal string representing the data to be hashed.

    Output:
        str: A 64-character hexadecimal string representing the SHA-256 hash of the data.
    """
    data_bytes = bytes.fromhex(data_hex)
    hash_bytes = hashlib.sha256(data_bytes).digest()
    return hash_bytes.hex()

def ripemd160(data_hex):
    """
    Compute the RIPEMD-160 hash of the given data.

    Input:
        data_hex (str): A hexadecimal string representing the data to be hashed.

    Output:
        str: A 40-character hexadecimal string representing the RIPEMD-160 hash of the data.
    """
    data_bytes = bytes.fromhex(data_hex)
    hash_bytes = hashlib.new('ripemd160', data_bytes).digest()
    return hash_bytes.hex()

def add_network_byte(ripemd160_hash_hex):
    """
    Add the network byte to the RIPEMD-160 hash.

    Input:
        ripemd160_hash_hex (str): A 40-character hexadecimal string representing the RIPEMD-160 hash.

    Output:
        str: A 42-character hexadecimal string with '00' prepended to the RIPEMD-160 hash.
    """
    return '00' + ripemd160_hash_hex

def double_sha256(data_hex):
    """
    Compute the double SHA-256 hash of the given data.

    Input:
        data_hex (str): A hexadecimal string representing the data to be hashed.

    Output:
        str: A 64-character hexadecimal string representing the double SHA-256 hash of the data.
    """
    return sha256(sha256(data_hex))

def calculate_checksum(data_hex):
    """
    Calculate the checksum for the given data.

    Input:
        data_hex (str): A hexadecimal string representing the data for which the checksum is to be calculated.

    Output:
        str: An 8-character hexadecimal string representing the checksum.
    """
    return double_sha256(data_hex)[:8]

def append_checksum(data_hex, checksum_hex):
    """
    Append the checksum to the given data.

    Input:
        data_hex (str): A hexadecimal string representing the data to which the checksum is to be appended.
        checksum_hex (str): An 8-character hexadecimal string representing the checksum.

    Output:
        str: A hexadecimal string representing the data concatenated with the checksum.
    """
    return data_hex + checksum_hex

def base58_encode(data_hex):
    """
    Encode the given data into Base58.

    Input:
        data_hex (str): A hexadecimal string representing the data to be encoded.

    Output:
        str: A string representing the Base58 encoded data.
    """
    data_bytes = bytes.fromhex(data_hex)
    return base58.b58encode(data_bytes).decode('utf-8')


def generate_address():
    """
    Generate a P2PKH Bitcoin address along with its corresponding public and private keys.

    Output:
        tuple: A tuple containing the Bitcoin address (str), public key (str), and private key (str).
    """
    # Generate a random 256-bit private key
    private_key_hex = generate_private_key()
    
    # Derive the corresponding public key
    public_key_hex = private_to_public(private_key_hex)
    
    # Perform SHA-256 hashing on the public key
    sha256_hash = sha256(public_key_hex)
    
    # Perform RIPEMD-160 hashing on the result of SHA-256
    ripemd160_hash = ripemd160(sha256_hash)
    
    # Add network byte (00 for Bitcoin mainnet)
    network_byte_added = add_network_byte(ripemd160_hash)
    
    # Perform double SHA-256 hashing and take the first 4 bytes as checksum
    checksum = calculate_checksum(network_byte_added)
    
    # Append the checksum to the extended RIPEMD-160 hash
    full_hash = append_checksum(network_byte_added, checksum)
    
    # Convert the result into a Base58 string
    bitcoin_address = base58_encode(full_hash)

    return bitcoin_address, public_key_hex, private_key_hex

def find_custom_address(desired_second_char, desired_third_char):
    """
    Run the address generation algorithm in a loop until an address with the desired second and third characters is found.

    Input:
        desired_second_char (str): The desired character for the second position in the address.
        desired_third_char (str): The desired character for the third position in the address.

    Output:
        tuple: A tuple containing the Bitcoin address (str), public key (str), and private key (str) that meet the criteria.
    """
    while True:
        bitcoin_address, public_key, private_key = generate_address()
        if bitcoin_address[1] == desired_second_char and bitcoin_address[2] == desired_third_char:
            return bitcoin_address, public_key, private_key

