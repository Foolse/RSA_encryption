#!/usr/local/bin/python3

import random
import base64

'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def gen_priv_key(e, phi):
    n = 1
    while n < phi:
        x = e*n % phi
        if x == 1:
            return n
        else:
            n = n + 1

    print("could not find a Private exponent!")
    exit()


'''
Tests to see if a number is prime.
'''


def is_prime(num):
    num = abs(int(num))
# Below two is no primes
    if num < 2:
        return False
# Two is a prime
    if num == 2:
        return True
# Checks if the number is even
    if not num & 1:
        return False
# This checks if the number is lower than 2 or if it is even
    if num < 2 or num % 2 == 0:
        return False
# Checks if there are any possible dividents for num
# apart from 1 and 2 checks until half of num
    for n in range(3, int(num**0.5) + 1, 2):
        if num % n == 0:
            return False
# If nothing else, the number should be a prime
    return True


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        print('\n \t Both numbers must be prime. \n')
        exit()
    elif p == q:
        print('\n \t p and q cannot be equal\n')
        exit()
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    # Use Euclid's Algorithm to verify that e and phi(n) are comprime

    g = 0
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = gen_priv_key(e, phi)

    return ((e, n), (d, n))


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    cipher = ''.join(str(cipher))
    # This is not really nescessary but used for packing the message more compact
    cipher_64 = str(cipher).encode()
    cipher_64 = base64.b64encode(cipher_64)
    # Return the array of bytes
    return cipher_64


def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((int(char) ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    string_return = ''.join(plain)
    return string_return


if __name__ == '__main__':
    '''
    Detect if the script is being run directly by the user
    '''
    choice = 'a'
    print("RSA Encrypter/ Decrypter")
    while choice != 'q':
        choice = input(
            "Create the keys (c), encrypt(e) or decrypt(d) or quit(q)?")

        # Create the keys
        if choice == 'c':
            p = int(input("Enter a prime number (17, 19, 23, etc): "))
            q = int(input("Enter another prime number (Not one you entered above): "))

            print ("Generating your public/private keypairs now . . .")
            public, private = generate_keypair(p, q)
            print(private)
            print ("Your public key is " + str(public) +
                   " and your private key is " + str(private))

        # Encryption
        elif choice == 'e':
            message = input(
                "Enter a message to encrypt with your public key: ")
            private, exponent = input(
                "Enter your public key in the form nnn mmm: ").split()
            encrypted_msg = encrypt((int(private), int(exponent)), message)
            print ("\n \t Your encrypted message is: ")
            print(encrypted_msg)

        # Decryption
        elif choice == 'd':
            message = input("Enter your encrypted message: ")
            public, exponent = input(
                "Enter your private key in the form nnn mmm: ").split()

            print ("Decrypting message with private key ",
                   public, exponent, " . . .")
            # decoding the base64 and utf-8 encodings
            message_array = base64.b64decode(message)
            message_array = message_array.decode()
            # removind the first and last characters as these are [ and ]
            message_array = message_array[1:-1]
            # splitting up the string on the delimiting ',' characters
            message_array = message_array.split(',')

            print ("Your message is:")
            print (decrypt((int(public), int(exponent)), message_array))
