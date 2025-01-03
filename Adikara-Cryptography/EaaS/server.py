#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

SECRET_KEY = get_random_bytes(16)
FLAG = open("flag.txt", "rb").read()
BLOCK_SIZE = 16

def encrypt(data: bytes) -> bytes:
    """
    Encrypts the provided data using AES in ECB mode.
    Pads the data to ensure it is a multiple of the block size.
    """
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded = pad(data + FLAG, BLOCK_SIZE)
    return cipher.encrypt(padded)

def display_menu() -> str:
    """
    Displays the menu options and retrieves the user's choice.
    """
    print("Options:")
    print("  [1] Encrypt")
    print("  [2] Exit")
    return input("Enter your choice: ").strip()

def handle_encryption() -> None:
    """
    Handles the encryption process by taking user input,
    encrypting it, and displaying the result.
    """
    try:
        user_message = input("Enter your message: ").encode()
        encrypted_message = encrypt(user_message)
        print(f"Encrypted: {encrypted_message.hex()}")
    except Exception as e:
        print(f"Error: {e}")

def main() -> None:
    """
    Main function that runs the Adikara Encryption System.
    """
    print("== Adikara Encryption System ==")
    while True:
        choice = display_menu()
        if choice == "1":
            handle_encryption()
        elif choice == "2":
            print("Goodbye!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
