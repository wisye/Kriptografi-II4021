import math
from itertools import count


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x


def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd({a}, {m}) = {gcd})")
    else:
        return x % m


def decrypt_affine(ciphertext, m, b, n):
    m_inv = mod_inverse(m, n)
    plaintext = [(hex((m_inv * (int(value, 16) - b)) % n)) for value in ciphertext]
    return plaintext


def decode_image_without_keys(encrypted_image_path, output_path):
    # Read the encrypted image bytes
    with open(encrypted_image_path, "rb") as image:
        encrypted_bytes = bytearray(image.read())
   
    # Convert the bytes to hexadecimal
    encrypted_hex = [hex(byte) for byte in encrypted_bytes]
   
    png_signature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    n = 256
   
    # Using the first two bytes to solve for m and b
    c1 = int(encrypted_hex[0], 16)
    c2 = int(encrypted_hex[1], 16)
    p1 = png_signature[0]  # 0x89
    p2 = png_signature[1]  # 0x50
   
    # Find m using the equation: m * (p₁ - p₂) ≡ (c₁ - c₂) (mod 256)
    diff_c = (c1 - c2) % 256
    diff_p = (p1 - p2) % 256


    # Find m by solving the congruence
    for possible_m in count(1):
        if possible_m >= 256:
            break
        if math.gcd(possible_m, 256) == 1 and (possible_m * diff_p) % 256 == diff_c:
            m = possible_m
            # Find b by substituting
            b = (c1 - (m * p1) % 256) % 256
           
            # Verify solution by using more bytes of the PNG signature
            decrypted = decrypt_affine(encrypted_hex[:8], m, b, n)
            decoded_signature = [int(hex_val, 16) for hex_val in decrypted]
           
            if decoded_signature == png_signature:
                print(f"Found valid parameters: m={m}, b={b}")
               
                # Decrypt the entire image
                decrypted_hex = decrypt_affine(encrypted_hex, m, b, n)
                decrypted_bytes = bytearray()
                for hex_value in decrypted_hex:
                    byte_value = int(hex_value, 16)
                    decrypted_bytes.append(byte_value)
               
                # Write the decrypted image
                with open(output_path, "wb") as file:
                    file.write(decrypted_bytes)
                print(f"Decrypted image saved to {output_path}")
                return True
           
if __name__ == "__main__":
    encrypted_image_path = "./encrypted.png"
    output_path = "./decrypted.png"
    decode_image_without_keys(encrypted_image_path, output_path)