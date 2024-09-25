import sys

def caesar_cipher(text, shift):
    """
    Encrypts or decrypts a given text using the Caesar Cipher algorithm.

    Args:
        text (str): The text to be encrypted or decrypted.
        shift (int): The number of positions each letter will be shifted down the alphabet.

    Returns:
        str: The encrypted or decrypted text.
    """

    result = ""

    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char

    return result


# Example usage:

text_to_encrypt = sys.argv[1]
shift_value = 3

encrypted_text = caesar_cipher(text_to_encrypt, shift_value)
print("Encrypted text:", encrypted_text)

decrypted_text = caesar_cipher(encrypted_text, -shift_value)
print("Decrypted text:", decrypted_text)
