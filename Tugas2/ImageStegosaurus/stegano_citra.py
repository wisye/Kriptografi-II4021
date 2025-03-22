from lsb import encode_lsb, decode_lsb, calculate_psnr
from bpcs import encode_bpcs, decode_bpcs

def main():
    while True:
        stego_key = None
        encryption_type = None

        mode = input("Choose embedding or extracting: ")

        if mode == "embedding":
            cover_path = input("Enter cover image path: ")
            cover_path = "media/" + cover_path

            msg_path = input("Enter message path: ")
            msg_path = "media/" + msg_path

            stego_path = input("Enter stego path: ")
            stego_path = "stego/" + stego_path

            is_encrypting = input("Encrypt message? (y/n): ")
            if is_encrypting == 'y':
                while (stego_key == None or len(stego_key) > 25):
                    stego_key = input("Enter secret key: ")
                encryption_type = 'vigenere'

            stego_method = input("Enter stego method: ")
            if stego_method == "lsb":
                is_sequential = input("Use sequential embedding? (y/n): ")
                if is_sequential == 'y':
                    is_sequential = True
                else:
                    while (stego_key == None or len(stego_key) > 25):
                        stego_key = input("Enter secret key: ")
                    is_sequential = False
                encode_lsb(cover_path, msg_path, stego_path, stego_key, encryption_type, is_sequential)

            elif stego_method == "bpcs":
                threshold = float(input("Enter threshold [0.1, 0.5] (default: 0.3): "))
                encode_bpcs(cover_path, msg_path, stego_path, threshold=threshold, stego_key=stego_key, encryption_type=encryption_type)
            
            print("PSNR:", calculate_psnr(cover_path, stego_path))
    
        elif mode == "extracting":
            stego_path = input("Enter stego path: ")
            stego_path = "stego/" + stego_path

            extraction_path = input ("Enter extraction path: ")
            extraction_path = "extraction/" + extraction_path

            is_encrypting = input("Encrypt message? (y/n): ")
            if is_encrypting == 'y':
                while (stego_key == None or len(stego_key) > 25):
                    stego_key = input("Enter secret key: ")
                encryption_type = 'vigenere'

            stego_method = input("Enter stego method: ")
            if stego_method == "lsb": 
                is_sequential = input("Use sequential embedding? (y/n): ")
                if is_sequential == 'y':
                    is_sequential = True
                else:
                    while (stego_key == None or len(stego_key) > 25):
                        stego_key = input("Enter secret key: ")
                    is_sequential = False
                decode_lsb(stego_path, extraction_path, stego_key, encryption_type, is_sequential)

            elif stego_method == "bpcs":
                threshold = float(input("Enter threshold [0.1, 0.5] (default: 0.3): "))
                decode_bpcs(stego_path, extraction_path, threshold=threshold, stego_key=stego_key, encryption_type=encryption_type)
    
main()
