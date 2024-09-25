import sys
def vigenere_cipher(text, key):
    """
    Encrypts or decrypts a given text using the Vigenère cipher algorithm.

    Args:
        text (str): The text to be encrypted or decrypted.
        key (str): The keyword used for encryption and decryption.

    Returns:
        str: The encrypted or decrypted text.
    """

    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = ""

    key_index = 0
    for char in text:
        if char.isalpha():
            position = alphabet.index(char.lower())
            shift = alphabet.index(key[key_index % len(key)].lower())

            new_position = (position + shift) % 26

            result += alphabet[new_position] if char.islower() else alphabet[new_position].upper()

            key_index += 1
        else:
            result += char

    return result

def vigenere_decipher(text, key):
    """
    Decrypts a given text that was previously encrypted using the Vigenère cipher algorithm.

    Args:
        text (str): The text to be decrypted.
        key (str): The keyword used for decryption.

    Returns:
        str: The decrypted text.
    """

    alphabet = "abcdefghijklmnopqrstuvwxyz"
    result = ""

    key_index = 0
    for char in text:
        if char.isalpha():
            position = alphabet.index(char.lower())
            shift = alphabet.index(key[key_index % len(key)].lower())

            new_position = (position - shift) % 26

            result += alphabet[new_position] if char.islower() else alphabet[new_position].upper()

            key_index += 1
        else:
            result += char

    return result


# Example usage:

key = "segredo"

encrypted_text = vigenere_cipher(sys.argv[1], key)
print("Encrypted text:", encrypted_text)

decrypted_text = vigenere_decipher(encrypted_text, key)  # decryption

print("Decrypted text:", decrypted_text)
