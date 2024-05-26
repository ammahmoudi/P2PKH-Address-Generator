from utils import find_custom_address


def __main__():
    # Example usage:
    desired_second_char = 'n'  # Replace with your desired character
    desired_third_char = 'f'  # Replace with your desired character

    bitcoin_address, public_key, private_key = find_custom_address(desired_second_char, desired_third_char)
    print(f"Bitcoin Address: {bitcoin_address}")
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")

if __name__ == '__main__':
    __main__()