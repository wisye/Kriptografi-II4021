from stegano_api import encode_lsb, decode_lsb, verify_lsb

def main():
    cover_path = "media/hello.png"
    msg_path = "media/sucipto.jpeg"
    stego_path = "stego/sucipto.png"
    extraction_path = "extraction/sucipto.jpeg"
    stego_key = 'secretkey'
    encryption_type = 'vigenere'
    is_sequential = False

    encode_lsb(cover_path, msg_path, stego_path, stego_key, encryption_type, is_sequential)
    decode_lsb(stego_path, extraction_path, stego_key, encryption_type, is_sequential)
    
    verify_lsb(msg_path, extraction_path)
    
main()