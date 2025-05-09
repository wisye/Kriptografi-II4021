from PIL import Image
import os
import random
import numpy as np
from math import ceil


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
    flags = format(0, '08b')

    return msg_ext_bin + msg_length_bin + flags


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


def get_bit_planes(image, channel):
    height, width = image.shape[0], image.shape[1]
    planes = []

    for bit in range(8):
        plane = np.zeros((height, width), dtype=np.uint8)
        mask = 1 << bit
        for y in range(height):
            for x in range(width):
                plane[y, x] = 1 if (image[y, x, channel] & mask) > 0 else 0
        planes.append(plane)

    return planes


def set_bit_planes(image, channel, planes):
    height, width = image.shape[0], image.shape[1]

    image[:, :, channel] = 0  # Clear the channel

    for bit in range(8):
        for y in range(height):
            for x in range(width):
                if planes[bit][y, x] == 1:
                    image[y, x, channel] |= (1 << bit)

    return image


def calculate_complexity(block):
    height, width = block.shape
    changes = 0

    for y in range(height):
        for x in range(width - 1):
            if block[y, x] != block[y, x + 1]:
                changes += 1

    for x in range(width):
        for y in range(height - 1):
            if block[y, x] != block[y + 1, x]:
                changes += 1

    max_changes = 2 * height * width - height - width

    return changes / max_changes


def conjugate(block):
    height, width = block.shape
    conjugated = np.zeros((height, width), dtype=np.uint8)

    for y in range(height):
        for x in range(width):
            conjugated[y, x] = block[y, x] ^ ((x + y) % 2)

    return conjugated


def deconjugate(block):
    height, width = block.shape
    deconjugated = np.zeros((height, width), dtype=np.uint8)

    for y in range(height):
        for x in range(width):
            deconjugated[y, x] = block[y, x] ^ ((x + y) % 2)

    return deconjugated


def binary_to_blocks(binary_data, block_size=8):
    bits_per_block = block_size * block_size
    blocks = []

    remainder = len(binary_data) % bits_per_block
    padding_needed = 0 if remainder == 0 else bits_per_block - remainder

    if padding_needed > 0:
        binary_data += '0' * padding_needed

    num_blocks = len(binary_data) // bits_per_block
    for i in range(num_blocks):
        start = i * bits_per_block
        end = start + bits_per_block
        block_data = binary_data[start:end]

        block = np.zeros((block_size, block_size), dtype=np.uint8)
        for j, bit in enumerate(block_data):
            y = j // block_size
            x = j % block_size
            block[y, x] = int(bit)

        blocks.append(block)

    return blocks, padding_needed


def blocks_to_binary(blocks, block_size=8, padding=0):
    binary_data = ""

    if isinstance(blocks, np.ndarray) and blocks.ndim == 2:
        blocks = [blocks]

    for block in blocks:
        for y in range(block_size):
            for x in range(block_size):
                binary_data += str(block[y, x])

    if padding > 0 and padding < len(binary_data):
        binary_data = binary_data[:-padding]

    return binary_data


def encode_bpcs(cover_file: str, msg_file: str, output_file: str, threshold: float = 0.3,
                stego_key: str = None, encryption_type: str = None):
    cover_px = file_to_px(cover_file)
    height, width, channels = cover_px.shape

    block_height = (height // 8) * 8
    block_width = (width // 8) * 8

    msg = file_to_bin(msg_file)
    msg_length = len(msg) // 8
    msg_ext = get_ext(msg_file)

    prefix = create_prefix(msg_ext, msg_length)

    full_msg = prefix + msg

    if encryption_type == 'vigenere' and stego_key:
        full_msg = encrypt_vigenere(full_msg, stego_key)

    message_blocks, padding = binary_to_blocks(full_msg)

    max_blocks_per_channel = (block_height // 8) * (block_width // 8) * 7
    max_possible_blocks = max_blocks_per_channel * channels

    estimated_usable_blocks = int(max_possible_blocks * 0.4)

    if len(message_blocks) > estimated_usable_blocks:
        print(
            f"Required blocks: {len(message_blocks)}, Estimated capacity: {estimated_usable_blocks} blocks")
        exit()

    stego_px = cover_px.copy()

    info_binary = format(len(message_blocks), '032b') + format(padding, '032b')

    if encryption_type == 'vigenere' and stego_key:
        info_binary = encrypt_vigenere(info_binary, stego_key)

    info_index = 0
    for x in range(22):  # 22 pixels * 3 channels = 64
        for c in range(channels):
            if info_index < len(info_binary):
                stego_px[0, x, c] = (stego_px[0, x, c] & 0xFE) | int(
                    info_binary[info_index])
                info_index += 1

    block_count = len(message_blocks)
    embedded_blocks = 0
    conjugation_map = []  

    for channel in range(channels):
        if embedded_blocks >= block_count:
            break

        bit_planes = get_bit_planes(
            stego_px[:block_height, :block_width], channel)

        for plane_idx in range(7, 0, -1):  
            if embedded_blocks >= block_count:
                break

            plane = bit_planes[plane_idx]

            for y_block in range(0, block_height, 8):
                for x_block in range(0, block_width, 8):
                    if embedded_blocks >= block_count:
                        break

                    current_block = plane[y_block:y_block+8, x_block:x_block+8]

                    complexity = calculate_complexity(current_block)

                    if complexity >= threshold:
                        msg_block = message_blocks[embedded_blocks]

                        msg_complexity = calculate_complexity(msg_block)
                        is_conjugated = False

                        if msg_complexity < threshold:
                            msg_block = conjugate(msg_block)
                            is_conjugated = True

                        plane[y_block:y_block+8, x_block:x_block+8] = msg_block

                        conjugation_map.append(is_conjugated)

                        embedded_blocks += 1

            bit_planes[plane_idx] = plane

        stego_px[:block_height, :block_width] = set_bit_planes(
            stego_px[:block_height, :block_width], channel, bit_planes)

    conj_binary = ''.join('1' if conj else '0' for conj in conjugation_map)

    while len(conj_binary) % 8 != 0:
        conj_binary += '0'

    conj_size_binary = format(len(conj_binary) // 8, '032b')
    print(
        f"Conjugation map size: {len(conj_binary) // 8} bytes, with {len(conjugation_map)} entries")

    if encryption_type == 'vigenere' and stego_key:
        conj_binary = encrypt_vigenere(conj_binary, stego_key)
        conj_size_binary = encrypt_vigenere(conj_size_binary, stego_key)

    conj_size_index = 0
    for x in range(11):  # 11 pixels * 3 channels -> 32
        for c in range(channels):
            if conj_size_index < len(conj_size_binary):
                stego_px[1, x, c] = (stego_px[1, x, c] & 0xFE) | int(
                    conj_size_binary[conj_size_index])
                conj_size_index += 1

    conj_index = 0
    row = 2
    col = 0

    while conj_index < len(conj_binary):
        stego_px[row, col, conj_index % channels] = (
            stego_px[row, col, conj_index % channels] & 0xFE) | int(conj_binary[conj_index])
        conj_index += 1

        if conj_index % channels == 0:
            col += 1
            if col >= width:  
                col = 0
                row += 1

    save_img(stego_px, output_file)
    print(f"BPCS stego image saved to {output_file}")
    print(f"Embedded {embedded_blocks} blocks with threshold {threshold}")


def decode_bpcs(stego_file: str, output_file: str, threshold: float = 0.3,
                stego_key: str = None, encryption_type: str = None):
    stego_px = file_to_px(stego_file)
    height, width, channels = stego_px.shape

    block_height = (height // 8) * 8
    block_width = (width // 8) * 8

    info_binary = ""
    for x in range(22):
        for c in range(channels):
            if len(info_binary) < 64:
                info_binary += str(stego_px[0, x, c] & 1)

    if encryption_type == 'vigenere' and stego_key:
        info_binary = decrypt_vigenere(info_binary, stego_key)

    block_count = int(info_binary[:32], 2)
    padding = int(info_binary[32:64], 2)

    conj_size_binary = ""
    for x in range(11):  
        for c in range(channels):
            if len(conj_size_binary) < 32:
                conj_size_binary += str(stego_px[1, x, c] & 1)

    if encryption_type == 'vigenere' and stego_key:
        conj_size_binary = decrypt_vigenere(conj_size_binary, stego_key)

    conj_map_size = int(conj_size_binary, 2)

    conj_binary = ""
    conj_index = 0
    row = 2
    col = 0

    while conj_index < conj_map_size * 8:
        conj_binary += str(stego_px[row, col, conj_index % channels] & 1)
        conj_index += 1

        if conj_index % channels == 0: 
            col += 1
            if col >= width:  
                col = 0
                row += 1

    if encryption_type == 'vigenere' and stego_key:
        conj_binary = decrypt_vigenere(conj_binary, stego_key)

    conjugation_map = [bit == '1' for bit in conj_binary[:block_count]]

    message_blocks = []
    block_found = 0
    block_locations = []  

    for channel in range(channels):
        if block_found >= block_count:
            break

        bit_planes = get_bit_planes(
            stego_px[:block_height, :block_width], channel)

        for plane_idx in range(7, 0, -1):  
            if block_found >= block_count:
                break

            plane = bit_planes[plane_idx]

            for y_block in range(0, block_height, 8):
                for x_block in range(0, block_width, 8):
                    if block_found >= block_count:
                        break

                    current_block = plane[y_block:y_block+8, x_block:x_block+8]

                    complexity = calculate_complexity(current_block)

                    if complexity >= threshold:
                        block_locations.append(
                            (channel, plane_idx, y_block, x_block))

                        if block_found < len(conjugation_map) and conjugation_map[block_found]:
                            message_block = deconjugate(current_block)
                        else:
                            message_block = current_block.copy()

                        message_blocks.append(message_block)
                        block_found += 1

    binary_data = blocks_to_binary(message_blocks, padding=padding)

    header_bits = PREFIX_BYTES * 8
    if len(binary_data) < header_bits:
        print(
            f"Error: Binary extracting header bits)")
        return

    header_binary = binary_data[:header_bits]

    if encryption_type == 'vigenere' and stego_key:
        binary_data = decrypt_vigenere(binary_data, stego_key)
        header_binary = binary_data[:header_bits]

    msg_ext, msg_length = parse_prefix(header_binary)

    total_bits = header_bits + (msg_length * 8)

    message_binary = binary_data[header_bits:total_bits]

    with open(output_file, 'wb') as f:
        for i in range(0, len(message_binary), 8):
            if i+8 <= len(message_binary):
                byte = int(message_binary[i:i+8], 2)
                f.write(byte.to_bytes(1, byteorder='big'))

    print(f"Message extracted and saved to {output_file}")
    print(f"Extracted {block_found} blocks with threshold {threshold}")