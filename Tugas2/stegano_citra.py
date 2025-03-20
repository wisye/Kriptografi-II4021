import stegano_api as steg

def encode_citra(cover_file: str, msg_file: str, output_file: str, key: str, is_encrypted: bool, is_sequential: bool):
        prefix = steg.create_prefix(msg_file, is_encrypted, is_sequential)
        msg = steg.file_to_bin(msg_file)
        
        if is_encrypted:
                msg = steg.encrypt_vigenere(msg, key)
                print(msg)

        if is_sequential:
                steg.encode_lsb(cover_file, prefix, msg, output_file, key, is_sequential)

def decode_citra(stego_file: str, output_file: str, key: str, is_encrypted: bool, is_sequential: bool):
        msg = steg.decode_lsb(stego_file, key)
        
        if is_encrypted:
                msg = steg.decrypt_vigenere(msg, key)
        
        steg.bin_to_file(msg, output_file)
        

encode_citra('sucipto.jpeg', 'hello.png', 'output.png', 'asdfhalf', True, True)
decode_citra('output.png', 'extracted.png', 'asdfhalf', True, True)