from PIL import Image
import os
import random
import numpy as np
import cv2

PREFIX_BYTES = 9


def file_to_px(file: str) -> np.array:
    img = Image.open(file).convert('RGB')
    return np.array(img)


def file_to_bin(msg_file: str) -> str:
    with open(msg_file, 'rb') as f:
        return (''.join(format(byte, '08b') for byte in f.read()))


def bytes_to_bin(msg: bytes) -> str:
    binary = ''
    for byte in msg:
        binary += format(byte, '08b')
    return binary


def get_ext(msg_file: str) -> str:
    _, ext = os.path.splitext(msg_file)
    return ext[1:].lower()


def save_img(px: np.array, output_file: str):
    img = Image.fromarray(px.astype('uint8'))
    img.save(output_file)


def encrypt_vigenere(msg: str, key: str) -> str:
    byte_list = []
    for i in range(0, len(msg), 8):
        chunk = msg[i:i+8]
        if len(chunk) == 8:
            byte_list.append(int(chunk, 2))

    key_bytes = key.encode('utf-8')
    key_length = len(key_bytes)

    encrypted_bytes = bytearray()
    for i, byte in enumerate(byte_list):
        encrypted_byte = (byte + key_bytes[i % key_length]) % 256
        encrypted_bytes.append(encrypted_byte)

    encrypted_bin = ''.join(format(byte, '08b') for byte in encrypted_bytes)

    return encrypted_bin


def decrypt_vigenere(encrypted_bin: str, key: str) -> str:
    byte_list = []
    for i in range(0, len(encrypted_bin), 8):
        chunk = encrypted_bin[i:i+8]
        if len(chunk) == 8:
            byte_list.append(int(chunk, 2))

    key_bytes = key.encode('utf-8')
    key_length = len(key_bytes)

    decrypted_bytes = bytearray()
    for i, byte in enumerate(byte_list):
        decrypted_byte = (byte - key_bytes[i % key_length] + 256) % 256
        decrypted_bytes.append(decrypted_byte)

    msg = ''.join(format(byte, '08b') for byte in decrypted_bytes)

    return msg


def create_prefix(msg_ext: str, msg_length: int) -> str:
    # Extension: 4 bytes
    # Length: 4 bytes
    # Flags: 1 byte

    ext_bytes = msg_ext.encode('ascii')
    if (len(ext_bytes) > 4):
        print("Extension too long")
        exit()
    while len(ext_bytes) < 4:
        ext_bytes += b'\x00'

    msg_ext_bin = bytes_to_bin(ext_bytes)
    msg_length_bin = format(msg_length, '032b')
    flags_bin = format(0, '08b')

    return msg_ext_bin + msg_length_bin + flags_bin


def parse_prefix(prefix: str) -> tuple:
    ext_binary = prefix[:32]
    length_binary = prefix[32:64]
    flag_binary = prefix[64:72]

    ext_bytes = bytearray()
    for i in range(0, len(ext_binary), 8):
        if i+8 <= len(ext_binary):
            ext_bytes.append(int(ext_binary[i:i+8], 2))

    ext = ext_bytes.replace(b'\x00', b'').decode('ascii', errors='ignore')

    msg_length = int(length_binary, 2)

    return ext, msg_length


def calculate_psnr(cover_file: str, stego_file: str) -> float:
    cover_file = file_to_px(cover_file)
    stego_file = file_to_px(stego_file)

    if cover_file.shape != stego_file.shape:
        raise ValueError("The two images must have the same dimensions")

    mse = np.mean((cover_file.astype(float) - stego_file.astype(float)) ** 2)
    if mse == 0:
        return float('inf')

    max_pixel = 255.0
    psnr = 20 * np.log10(max_pixel) - 10 * np.log10(mse)

    return psnr


def encode_lsb(cover_file: str, msg_file: str, output_file: str, stego_key: str = None,
               encryption_type: str = None, is_sequential: bool = True):
    cover_px = file_to_px(cover_file)
    height, width, channels = cover_px.shape

    msg = file_to_bin(msg_file)
    msg_length = len(msg) // 8
    msg_ext = get_ext(msg_file)

    prefix = create_prefix(msg_ext, msg_length)

    full_msg = prefix + msg

    if encryption_type == 'vigenere' and stego_key:
        full_msg = encrypt_vigenere(full_msg, stego_key)

    capacity = height * width * channels
    if len(full_msg) > capacity:
        print(
            f"Message too long. Need {len(full_msg)} bits, but only have {capacity} bits.")
        exit()

    px_pos = [(x, y) for y in range(height) for x in range(width)]
    if stego_key and not is_sequential:
        random.seed(stego_key)
        random.shuffle(px_pos)

    stego_px = cover_px.copy()

    index = 0
    for x, y in px_pos:
        if index >= len(full_msg):
            break

        for c in range(channels):
            if index >= len(full_msg):
                break
            stego_px[y, x, c] = stego_px[y, x, c] & 0xFE
            stego_px[y, x, c] = stego_px[y, x, c] | int(full_msg[index])
            index += 1

    save_img(stego_px, output_file)
    print(f"Stego image saved to {output_file}")


def decode_lsb(stego_file: str, output_file: str, stego_key: str = None,
               encryption_type: str = None, is_sequential: bool = True):
    stego_px = file_to_px(stego_file)
    height, width, channels = stego_px.shape

    px_pos = [(x, y) for y in range(height) for x in range(width)]
    if stego_key and not is_sequential:
        random.seed(stego_key)
        random.shuffle(px_pos)

    prefix_bits = PREFIX_BYTES * 8
    prefix_binary = ""

    # Decode prefix
    index = 0
    for x, y in px_pos:
        if index >= prefix_bits:
            break

        for c in range(channels):
            if index < prefix_bits:
                prefix_binary += str(stego_px[y, x, c] & 1)
                index += 1
            else:
                break

    if encryption_type == 'vigenere' and stego_key:
        prefix_binary = decrypt_vigenere(prefix_binary, stego_key)

    msg_ext, msg_length = parse_prefix(prefix_binary)

    total_bits = prefix_bits + (msg_length * 8)
    full_binary = ""

    # Decode message
    index = 0
    for x, y in px_pos:
        if index >= total_bits:
            break

        for c in range(channels):
            if index < total_bits:
                # Extract the LSB
                full_binary += str(stego_px[y, x, c] & 1)
                index += 1
            else:
                break

    if encryption_type == 'vigenere' and stego_key:
        full_binary = decrypt_vigenere(full_binary, stego_key)

    message_binary = full_binary[prefix_bits:]

    _, output_ext = os.path.splitext(output_file)
    output_ext = output_ext[1:].lower() if output_ext else ""

    if output_ext != msg_ext and msg_ext:
        output_base = os.path.splitext(output_file)[0]
        output_file = f"{output_base}.{msg_ext}"
        print(
            f"Changed output file extension to match embedded file: {output_file}")

    with open(output_file, 'wb') as f:
        for i in range(0, len(message_binary), 8):
            if i+8 <= len(message_binary):
                byte = int(message_binary[i:i+8], 2)
                f.write(byte.to_bytes(1, byteorder='big'))

    print(f"Message saved to {output_file}")
