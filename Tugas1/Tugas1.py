from collections import Counter
import string
from math import gcd
from functools import reduce
import re

def read_file(filename: str):
        with open(filename, 'r') as f:
                return f.read()
        
def write_file(filename: str, text: str):
        with open(filename, 'w') as f:
                f.write(text)

def format_counts(counts: dict):
        retval = ""
        for letter, count in sorted(counts.items(), key=lambda item: item[1], reverse=True):
                retval += (f"{letter}: {count}\n")
                
def count_letter(text: str):
        filtered = ''.join(map(lambda char: char if char in string.ascii_uppercase else '', text))
        filtered_counts = Counter(filtered)
        for letter in string.ascii_uppercase:
                if letter not in filtered_counts:
                        filtered_counts[letter] = 0
        return format_counts(filtered_counts)

def count_ngrams(text: str, n: int):
        filtered = ''.join(map(lambda char: char if char in string.ascii_uppercase else '', text))
        ngrams = [filtered[i:i+n] for i in range(len(filtered)-n+1)]
        return Counter(ngrams)

def no1(filename: str):
        ciphertext = read_file(filename)
        print(count_letter(ciphertext))
        
        bigram_counts = count_ngrams(ciphertext, 2)
        trigram_counts = count_ngrams(ciphertext, 3)
        
        print("\nTop 50 Bigrams:")
        for bigram, count in bigram_counts.most_common(50):
                print(f"{bigram}: {count}")
        
        print("\nTop 50 Trigrams:")
        for trigram, count in trigram_counts.most_common(50):
                print(f"{trigram}: {count}")

        translation_table = str.maketrans({
                'V': 't',
                'E': 'e',
                'A': 'h',
                'P': 'a',
                'U': 'i',
                'Y': 's',
                'M': 'n',
                'B': 'r',
                'N': 'c',
                'S': 'g',
                'I': 'o',
                'K': 'p',
                'H': 'd',
                'Z': 'w',
                'X': 'b',
                'G': 'l',
                'O': 'y',
                'W': 'v',
                'L': 'k',
                'F': 'm',
                'R': 'u',
                'T': 'f',
                'J': 'q',
                'Q': 'j',
                'C': 'x',
                
        })
                
        substituted = ciphertext.translate(translation_table)
        write_file("no1ans.txt", (substituted))

def replace_with_dash(text: str):
        return ''.join('' if char.isupper() else char for char in text)

def kasiski_examination(text: str, n: int = 3):
        sequences = {}
        for i in range(len(text) - n + 1):
                seq = text[i:i+n]
                if seq in sequences:
                        sequences[seq].append(i)
                else:
                        sequences[seq] = [i]
        
        repeated_sequences = {seq: positions for seq, positions in sequences.items() if len(positions) > 1}
        
        distances = []
        for seq, positions in repeated_sequences.items():
                for i in range(len(positions) - 1):
                        distances.append(positions[i+1] - positions[i])
        
        return repeated_sequences, distances

def find_gcd_of_list(numbers):
        return reduce(gcd, numbers)

def possible_key_lengths(distances):
        gcd_counts = Counter()
        for i in range(len(distances)):
                for j in range(i + 1, len(distances)):
                        gcd_counts[gcd(distances[i], distances[j])] += 1
        return gcd_counts.most_common()

def split_into_block(ciphertext, key_length):
    blocks = [ciphertext[i:i + key_length] for i in range(0, len(ciphertext), key_length)]
    return blocks

def vig_frequency_analysis(text):
    # Count letter frequencies
    freq = {}
    total_letters = 0
    for char in text.upper():
        if char.isalpha():
            freq[char] = freq.get(char, 0) + 1
            total_letters += 1
    
    # Convert to percentages
    for char in freq:
        freq[char] = (freq[char] / total_letters) * 100
    
    return freq

def write_kaisiski_examination(filename: str):
        ciphertext = read_file("no2.txt")
        repeated_sequences, distances = kasiski_examination(ciphertext)
        # counted = format_counts(count_letter(ciphertext))
        
        with open(filename, 'w') as f:
                # f.write(counted)
                
                f.write("Top 50 Bigrams:\n")
                bigram_counts = count_ngrams(ciphertext, 2)
                for bigram, count in bigram_counts.most_common(50):
                        f.write(f"{bigram}: {count}\n")
                
                f.write("\nTop 50 Trigrams:\n")
                trigram_counts = count_ngrams(ciphertext, 3)
                for trigram, count in trigram_counts.most_common(50):
                        f.write(f"{trigram}: {count}\n")
                
                exact_seq = ""
                f.write("\nRepeated Sequences and their Positions:\n")
                for seq, positions in repeated_sequences.items():
                        f.write(f"{seq}: {positions}\n")
                        # Repeated Sequences with distance = 12
                        if len(positions) > 1 and positions[1] - positions[0] == 12:
                                exact_seq += seq + " "

                f.write("\nRepeated Sequences with Distance = 12:\n")
                f.write(f"{exact_seq}\n")

                
                f.write("\nDistances between Repeated Sequences:\n")
                f.write(f"{distances}\n")
                
                gcd_counts = possible_key_lengths(distances)
                f.write("\nPossible Key Lengths:\n")
                for length, count in gcd_counts:
                        f.write(f"Length: {length}, Count: {count}\n")


def write_frequency_analysis(filename: str, ciphertext: str, key_length: int):
        with open(filename, 'w') as f:
                # Split the ciphertext into columns
                blocks = split_into_block(ciphertext.upper(), key_length)
                f.write("Split the ciphertext into blocks of key_length length:\n")
                for block in blocks:
                        formatted_block = ' '.join(block)
                        f.write(f"{formatted_block}\n")
        
                # Most popular letter per position in blocks
                f.write("\nMost popular letter per position in blocks:\n")
                for i in range(key_length):
                        column = ''.join(block[i] for block in blocks if i < len(block))
                        freq = vig_frequency_analysis(column)
                        most_popular_letter = max(freq, key=freq.get)
                        f.write(f"Position {i + 1}: {most_popular_letter} ({freq[most_popular_letter]:.2f}%)\n")

def decrypt_vigenere(ciphertext: str, key: list):
        decrypted_text = []
        key_length = len(key)
        for i, char in enumerate(ciphertext):
                if char in string.ascii_uppercase:
                        if key[i % key_length] == '':
                                decrypted_text.append(char.upper())
                        else:
                                shift = ord(key[i % key_length]) - ord('a')
                                decrypted_char = chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
                                decrypted_text.append(decrypted_char)
                else:
                        decrypted_text.append(char)
        return ''.join(decrypted_text)

def wrap_text(text: str, n: int):
        return '\n'.join(text[i:i+n] for i in range(0, len(text), n))

def no2(filename: str):
        ciphertext = read_file(filename)
        write_kaisiski_examination("no2analysis.txt")
        write_frequency_analysis("no2analysis2.txt", ciphertext, 12)

        with open("no2ans.txt", 'w') as f:
                key = ['L', 'Y', 'R', 'A', 'N', 'O', 'V', 'A', 'L', 'A', 'Y', 'R']
                decrypted_text = decrypt_vigenere(ciphertext, key)
                f.write(decrypted_text)



def no3(filename: str):
        ciphertext = read_file(filename)
        bigram_counts = count_ngrams(ciphertext, 2)
        trigram_counts = count_ngrams(ciphertext, 3)
        
        with open("no3analysis.txt", "w") as f:
                for bigram, count, in bigram_counts.most_common(100):
                        f.write(f"{bigram} : {count}\n")
                f.write("\n")
                for trigram, count, in trigram_counts.most_common(100):
                        f.write(f"{trigram} : {count}\n")

import numpy as np
from sympy import Matrix

def mod_inverse_matrix(matrix, mod):
    matrix = Matrix(matrix)  
    det = int(matrix.det())  
    
    # Compute modular inverse of determinant
    det_inv = pow(det, -1, mod)  
    if det_inv is None:
        raise ValueError("Matrix is not invertible under mod {}".format(mod))
    
    # Compute adjugate (cofactor matrix transpose)
    adjugate = matrix.adjugate()  

    # Compute modular inverse matrix
    inverse_matrix = (det_inv * adjugate) % mod  
    
    return np.array(inverse_matrix.tolist(), dtype=int)

def mod_matrix_multiply(A, B, mod):
    A = np.array(A)
    B = np.array(B)
    result = np.dot(A, B) % mod  
    return result

def text_to_matrix(text, n):
    text_numbers = [(ord(char) - ord('A')) for char in text.upper() if char.isalpha()]
    while len(text_numbers) % n != 0:
        text_numbers.append(0)  # Padding with 'A' (0) if needed
    
    return [text_numbers[i:i+n] for i in range(0, len(text_numbers), n)]

def matrix_to_text(matrix):
    text = "".join(chr((num % 26) + ord('A')) for row in matrix for num in row)
    return text


def hill_cipher_decrypt(key, ciphertext, mod, n):
    key_inv = mod_inverse_matrix(key, mod)
    ciphertext_matrices = text_to_matrix(ciphertext, n)
    
    print("Decrypted Matrices:")
    decrypted_text = ""
    for matrix in ciphertext_matrices:
        decrypted_matrix = mod_matrix_multiply(key_inv, matrix, mod)
        print(np.array(decrypted_matrix))
        decrypted_text += matrix_to_text([decrypted_matrix])
    
    return decrypted_text

def no4(filename: str):
    with open(filename, 'r') as file:
        ciphertext = file.read().strip()

    key = np.array([
        [6, 24, 1],
        [13, 16, 10],
        [20, 17, 15],
    ])
    mod = 26
    n = 3

    try:
        plaintext = hill_cipher_decrypt(key, ciphertext, mod, n)
        with open("no4ans.txt", 'w') as f:
            f.write(plaintext)
    except ValueError as e:
        print(e)
                
no2("no2.txt")