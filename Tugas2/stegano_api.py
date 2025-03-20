from PIL import Image
import os
import random


def file_to_bin(msg_file: str) -> str:
    with open(msg_file, 'rb') as f:
        return (''.join(format(byte, '08b') for byte in f.read()))


def str_to_bin(msg: str) -> str:
    # Prefix
    length = len(msg)
    bin_length = format(length, "016b")
    return bin_length + ''.join(format(ord(c), '08b') for c in msg)


def bin_to_str(bin_data: str) -> str:
    # Prefix
    length = int(bin_data[:16], 2)
    msg_bin = bin_data[16:16 + (length * 8)]
    ch = [msg_bin[i:i+8] for i in range(0, len(msg_bin), 8)]
    return ''.join(chr(int(c, 2)) for c in ch if int(c, 2) != 0)


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


def create_prefix(msg_file: str, is_encrypted: bool, is_sequential: bool) -> str:
    prefix = bytearray()

    # Extension: 3 bytes
    msg_ext = os.path.splitext(msg_file)[1][1:4]
    msg_length = os.path.getsize(msg_file)
    prefix.extend(bytes(msg_ext, 'utf-8'))
    prefix.extend(bytes([0] * (3 - len(msg_ext))))

    # Length: 3 bytes, up to 16.7 MB
    try:
        prefix.extend(msg_length.to_bytes(3, byteorder='big'))
    except OverflowError:
        print("Message too long")
        exit()

    # Flags: 1 byte
    flags = 0
    if is_encrypted:
        flags |= 1  # bit 0
    if is_sequential:
        flags |= 2  # bit 1
    prefix.extend(bytes([flags]))

    # Convert the bytearray to a binary string
    binary_string = ''.join(format(byte, '08b') for byte in prefix)

    return binary_string


def parse_prefix(prefix: str) -> tuple[str, int, bool, bool]:
    # Extension: 3 bytes
    extension_bits = prefix[0:24]
    extension_bytes = bytearray()
    for i in range(0, 24, 8):
        byte_value = int(extension_bits[i:i+8], 2)
        if byte_value != 0:
            extension_bytes.append(byte_value)
    extension = extension_bytes.decode('utf-8')

    # Length: 3 bytes
    size_bits = prefix[24:48]
    file_size = int(size_bits, 2)

    # Flags: 1 byte
    flag_bits = prefix[48:56]
    flags = int(flag_bits, 2)
    is_encrypted = bool(flags & 1)
    is_sequential = bool(flags & 2)

    return extension, file_size, is_encrypted, is_sequential


def encode_lsb(cover_file: str, prefix: str, msg: str, output_file: str, key: str, is_sequential: bool):
    img = Image.open(cover_file)
    pixels = list(img.getdata())

    if len(prefix) > len(pixels) * 3:
        print("Message too long")
        exit()

    encoded = []

    # Encode prefix
    index = 0
    for px in pixels[:len(prefix) // 3]:
        r, g, b = px[:3]
        if (index < len(prefix)):
            r = (r & ~1) | int(prefix[index])
            index += 1
        if (index < len(prefix)):
            g = (g & ~1) | int(prefix[index])
            index += 1
        if (index < len(prefix)):
            b = (b & ~1) | int(prefix[index])
            index += 1
        encoded.append((r, g, b) + px[3:] if len(px) == 4 else (r, g, b))

    # if is_sequential:
    #     positions = range(len(prefix), len(prefix) + len(msg))
    # else:
    #     # Non Sequential
    #     exit()

    # # Encode message
    # for px in pixels[len(prefix) + 1:]:
    #     r, g, b = px[:3]
    #     r = (r & ~1) | int(msg[index])
    #     index += 1
    #     g = (g & ~1) | int(msg[index])
    #     index += 1
    #     b = (b & ~1) | int(msg[index])
    #     index += 1
    #     encoded.append((r, g, b) + px[3:] if len(px) == 4 else (r, g, b))

    encoded_img = Image.new(img.mode, img.size)
    encoded_img.putdata(encoded)
    encoded_img.save(output_file)


def decode_lsb(cover_file: str, key: str, is_sequential: bool):
    img = Image.open(cover_file)
    pixels = list(img.getdata())

    msg = ''
    for px in pixels:
        r, g, b = px[:3]
        msg += str(r & 1)
        msg += str(g & 1)
        msg += str(b & 1)

    return parse_prefix(msg)

encode_lsb('sucipto.jpeg', create_prefix('hello.png', True, True), 'hello.png', 'output.png', 'asdfhalf', True)


# decode_lsb(encode_lsb('sucipto.jpeg', create_prefix('hello.png', True, True), 'hello.png', 'output.png', 'asdfhalf', True), file_to_bin('hello.png'), True)
