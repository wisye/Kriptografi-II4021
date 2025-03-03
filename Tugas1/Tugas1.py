from collections import Counter
import string
from math import gcd
from functools import reduce
import pycipher

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
                
                f.write("\nRepeated Sequences and their Positions:\n")
                for seq, positions in repeated_sequences.items():
                        f.write(f"{seq}: {positions}\n")
                
                f.write("\nDistances between Repeated Sequences:\n")
                f.write(f"{distances}\n")
                
                gcd_counts = possible_key_lengths(distances)
                f.write("\nPossible Key Lengths:\n")
                for length, count in gcd_counts:
                        f.write(f"Length: {length}, Count: {count}\n")

def insert_newlines(text: str, interval: int):
        return '\n'.join(text[i:i+interval] for i in range(0, len(text), interval))

def no2(filename: str):
        ciphertext = read_file(filename)
        write_kaisiski_examination("no2analysis.txt")
        
        separated = insert_newlines(ciphertext, 12).split('\n')
        with open("no2ans.txt", 'w') as f:
                for text in separated:
                        bigram_counts = count_ngrams(text, 2)
                        trigram_counts = count_ngrams(text, 3)
                        
                        f.write(f"\nText: {text}\n")
                        f.write("\nTop 5 Bigrams:\n")
                        for bigram, count in bigram_counts.most_common(5):
                                f.write(f"{bigram}: {count}\n")
                        
                        f.write("\nTop 5 Trigrams:\n")
                        for trigram, count in trigram_counts.most_common(5):
                                f.write(f"{trigram}: {count}\n")
                        
        

no2("no2.txt")