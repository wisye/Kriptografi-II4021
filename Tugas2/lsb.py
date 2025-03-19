from PIL import Image

def msg_to_bin(message: str):
        length = len(message)
        bin_length = format(length, "016b")
        return bin_length + ''.join(format(ord(c), '08b') for c in message)

def bin_to_msg(bin_data: str):
        length = int(bin_data[:16], 2)
        msg_bin = bin_data[16:16 + (length * 8)]
        ch = [msg_bin[i:i+8] for i in range(0, len(msg_bin), 8)]
        return ''.join(chr(int(c, 2)) for c in ch if int(c, 2) != 0)

def lsb(filename: str, msg: str, output: str):
        img = Image.open(filename)
        bin_msg = msg_to_bin(msg)
        pixels = list(img.getdata())
        
        if len(bin_msg) > len(pixels) * 3:
                print("Message too long")
                exit()
        
        encoded = []
        index = 0
        for px in pixels:
                r, g, b = px[:3]
                if index < len(bin_msg):
                        r = (r & ~1) | int(bin_msg[index])
                        index += 1
                if index < len(bin_msg):
                        g = (g & ~1) | int(bin_msg[index])
                        index += 1
                if index < len(bin_msg):
                        b = (b & ~1) | int(bin_msg[index])
                        index += 1
                encoded.append((r, g, b) + px[3:] if len(px) == 4 else (r, g, b))
        
        encoded_img = Image.new(img.mode, img.size)
        encoded_img.putdata(encoded)
        encoded_img.save(output)
        
def decode_lsb(filename: str):
        img = Image.open(filename)
        pixels = list(img.getdata())
        
        msg = ''
        for px in pixels:
                r, g, b = px[:3]
                msg += str(r & 1)
                msg += str(g & 1)
                msg += str(b & 1)
                
        return bin_to_msg(msg)

# lsb("sucipto.jpeg", "asidhosiahdasiodh", "sucipto2.png")
print(decode_lsb("sucipto2.png"))