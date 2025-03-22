import tkinter as tk
from tkinter import filedialog, messagebox
import wave
import random
import math
import base64
import os
import sys
import subprocess

# ===== Audio Player =====
def play_audio(path):
    if sys.platform.startswith('win'): # Windows
        os.startfile(path)
    elif sys.platform.startswith('darwin'): # MacOS
        subprocess.call(['open', path])
    else: # Linux ? 
        subprocess.call(['xdg-open', path])

# ===== Encryption =====
# Will encrypt/decrypt a normal plaintext into a ciphertext using vigenere cipher
# Key parameter: string (3-25 Chars)
def vigenere_encrypt(plaintext, key):
    ciphertext = []
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    plaintext_int = [ord(i) for i in plaintext]
    for i, char_val in enumerate(plaintext_int):
        value = (char_val + key_as_int[i % key_length]) % 256
        ciphertext.append(value)
    return bytes(ciphertext)

def vigenere_decrypt(ciphertext, key):
    plaintext = []
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    for i, byte_val in enumerate(ciphertext):
        value = (byte_val - key_as_int[i % key_length]) % 256
        plaintext.append(value)
    return bytes(plaintext)

# ===== WAV File Processing =====
def get_wave_params(wav_path):
    with wave.open(wav_path, 'rb') as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    return params, frames

def save_wave_file(wav_path, params, frames):
    with wave.open(wav_path, 'wb') as w:
        w.setparams(params)
        w.writeframes(frames)

def int_to_bytes(val, length=4):
    return val.to_bytes(length, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

# ===== LSB Steganography =====
def embed(cover_path, out_path, header_data, secret_data, randomize=False, seed=None):
    
    # Get Cover WAV Detail
    params, frames = get_wave_params(cover_path)
    n_channels, sampwidth, framerate, n_frames, comp_type, comp_name = params
    
    if sampwidth != 2: # 2 sampwidth = 16-bit PCM
        raise ValueError("Cover WAV must be 16-bit PCM.") # 16-bit PCM only

    samples = []
    
    for i in range(0, len(frames), 2):
        sample = frames[i] | (frames[i+1] << 8)
        samples.append(sample)

    total_samples = len(samples)
    capacity_bits = total_samples

    header_len_bits = len(header_data) * 8
    secret_len_bits = len(secret_data) * 8
    if (header_len_bits + secret_len_bits) > capacity_bits:
        raise ValueError("Not enough capacity.")

    # 1) Embed header sequentially in the first header_len_bits samples
    header_bits = []
    for byte_val in header_data:
        for bit_i in range(8):
            header_bits.append((byte_val >> bit_i) & 1)

    for i, bit_val in enumerate(header_bits):
        s = samples[i]
        s = s & 0xFFFE
        s |= bit_val
        samples[i] = s

    # 2) Embed secret data in the remaining samples
    secret_bits = []
    for byte_val in secret_data:
        for bit_i in range(8):
            secret_bits.append((byte_val >> bit_i) & 1)

    secret_indices = list(range(header_len_bits, header_len_bits + len(secret_bits)))
    if randomize and seed:
        random.seed(seed)
        random.shuffle(secret_indices)

    for i, bit_val in enumerate(secret_bits):
        idx = secret_indices[i]
        s = samples[idx]
        s = s & 0xFFFE
        s |= bit_val
        samples[idx] = s

    new_frames = bytearray()
    for s in samples:
        new_frames.append(s & 0xFF)
        new_frames.append((s >> 8) & 0xFF)

    new_params = (n_channels, sampwidth, framerate, n_frames, comp_type, comp_name)
    save_wave_file(out_path, new_params, new_frames)


def extract(stego_path, header_size, secret_size, randomize=False, seed=None):
    params, frames = get_wave_params(stego_path)
    n_channels, sampwidth, framerate, n_frames, comp_type, comp_name = params
    if sampwidth != 2:
        raise ValueError("Stego WAV must be 16-bit PCM.")

    samples = []
    for i in range(0, len(frames), 2):
        sample = frames[i] | (frames[i+1] << 8)
        samples.append(sample)

    total_samples = len(samples)
    capacity_bits = total_samples

    header_len_bits = header_size * 8
    secret_len_bits = secret_size * 8
    if (header_len_bits + secret_len_bits) > capacity_bits:
        raise ValueError("Not enough capacity.")

    # Extract header
    header_bits = []
    for i in range(header_len_bits):
        header_bits.append(samples[i] & 1)
    header_bytes = bytearray()
    for i in range(0, header_len_bits, 8):
        val = 0
        for b in range(8):
            val |= (header_bits[i+b] << b)
        header_bytes.append(val)

    # Extract secret
    secret_indices = list(range(header_len_bits, header_len_bits + secret_len_bits))
    if randomize and seed:
        random.seed(seed)
        random.shuffle(secret_indices)

    secret_bits = []
    for i in range(secret_len_bits):
        idx = secret_indices[i]
        secret_bits.append(samples[idx] & 1)

    secret_bytes = bytearray()
    for i in range(0, secret_len_bits, 8):
        val = 0
        for b in range(8):
            val |= (secret_bits[i+b] << b)
        secret_bytes.append(val)

    return bytes(header_bytes), bytes(secret_bytes)

# ===== PSNR Calculation =====
def compute_psnr(cover_path, stego_path):
    _, orig_frames = get_wave_params(cover_path)
    _, stego_frames = get_wave_params(stego_path)
    if len(orig_frames) != len(stego_frames):
        return 0.0

    orig_samples = []
    for i in range(0, len(orig_frames), 2):
        sample = orig_frames[i] | (orig_frames[i+1] << 8)
        orig_samples.append(sample)

    stego_samples = []
    for i in range(0, len(stego_frames), 2):
        sample = stego_frames[i] | (stego_frames[i+1] << 8)
        stego_samples.append(sample)

    mse = 0.0
    for osmp, ssmp in zip(orig_samples, stego_samples):
        diff = (osmp - ssmp)
        mse += diff * diff
    mse /= len(orig_samples)

    if mse == 0:
        return 999.99
    max_val = 32767
    psnr = 10.0 * math.log10((max_val * max_val) / mse)
    return psnr

# ===== Header =====
def build_header(file_name, extension, enc_bool, rand_bool, secret_data_len):
    fn_bytes = file_name.encode('utf-8')
    ext_bytes = extension.encode('utf-8')

    enc_byte = b'\x01' if enc_bool else b'\x00'
    r_byte = b'\x01' if rand_bool else b'\x00'

    data_len_bytes = int_to_bytes(secret_data_len, 4)
    fn_len_bytes = int_to_bytes(len(fn_bytes), 4)
    ext_len_bytes = int_to_bytes(len(ext_bytes), 4)

    header = fn_len_bytes + fn_bytes + ext_len_bytes + ext_bytes + enc_byte + r_byte + data_len_bytes
    return header

def parse_header(header_bytes):
    idx = 0
    def read_bytes(count):
        nonlocal idx
        seg = header_bytes[idx:idx+count]
        idx += count
        return seg

    fn_len = bytes_to_int(read_bytes(4))
    fn = read_bytes(fn_len).decode('utf-8', errors='ignore')

    ext_len = bytes_to_int(read_bytes(4))
    ext = read_bytes(ext_len).decode('utf-8', errors='ignore')

    enc_b = read_bytes(1)
    enc_bool = (enc_b[0] == 1)

    rand_b = read_bytes(1)
    rand_bool = (rand_b[0] == 1)

    d_len = bytes_to_int(read_bytes(4))

    return fn, ext, enc_bool, rand_bool, d_len


# ===== GUI =====
class AudioStegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Audio Steganography (LSB)")
        self.menu_frame = tk.Frame(self)
        self.menu_frame.pack(padx=20, pady=20)

        tk.Label(self.menu_frame, text="Choose an action:", font=("Arial", 14)).pack(side=tk.TOP, pady=5)
        tk.Button(self.menu_frame, text="Embed Data", font=("Arial", 12), command=self.goto_embed).pack(side=tk.LEFT, padx=10)
        tk.Button(self.menu_frame, text="Extract Data", font=("Arial", 12), command=self.goto_extract).pack(side=tk.LEFT, padx=10)

        self.embed_frame = EmbedFrame(self, self.menu_frame)
        self.extract_frame = ExtractFrame(self, self.menu_frame)

    def goto_embed(self):
        self.menu_frame.pack_forget()
        self.embed_frame.pack(padx=20, pady=20)

    def goto_extract(self):
        self.menu_frame.pack_forget()
        self.extract_frame.pack(padx=20, pady=20)

    def back_to_menu(self, frame):
        frame.pack_forget()
        self.menu_frame.pack(padx=20, pady=20)

class EmbedFrame(tk.Frame):
    def __init__(self, parent, menu_frame):
        super().__init__(parent)
        self.parent = parent
        self.menu_frame = menu_frame
        self.secret_file_path = None
        self.cover_file_path = None

        tk.Label(self, text="Embed Data into Audio", font=("Arial", 16, "bold"))\
            .grid(row=0, column=0, columnspan=4, pady=10)

        tk.Button(self, text="Select Secret File", command=self.select_secret_file)\
            .grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.secret_label = tk.Label(self, text="No file selected")
        self.secret_label.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        tk.Button(self, text="Select Cover .WAV", command=self.select_cover_file)\
            .grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.cover_label = tk.Label(self, text="No file selected")
        self.cover_label.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.cover_capacity_label = tk.Label(self, text="Capacity: N/A")
        self.cover_capacity_label.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        self.next_button = tk.Button(self, text="Next", command=self.check_capacity_and_ask, state=tk.DISABLED)
        self.next_button.grid(row=3, column=0, padx=5, pady=10, sticky="w")

        tk.Button(self, text="Back", command=lambda: parent.back_to_menu(self))\
            .grid(row=3, column=1, padx=5, pady=10, sticky="w")

    def select_secret_file(self):
        f = filedialog.askopenfilename(title="Select Secret File")
        if f:
            self.secret_file_path = f
            self.secret_label.config(text=os.path.basename(f))
            self.enable_if_ready()

    def select_cover_file(self):
        f = filedialog.askopenfilename(title="Select Cover Audio", filetypes=[("WAV files", "*.wav")])
        if f:
            self.cover_file_path = f
            self.cover_label.config(text=os.path.basename(f))
            self.show_capacity()
            self.enable_if_ready()

    def show_capacity(self):
        try:
            params, frames = get_wave_params(self.cover_file_path)
            if params.sampwidth != 2:
                self.cover_capacity_label.config(text="16-bit PCM only!")
                return
            total_samples = len(frames)//2
            overhead_bits = 200*8
            capacity_bits = total_samples - overhead_bits
            if capacity_bits<0: capacity_bits=0
            self.cover_capacity_label.config(text=f"Capacity: ~{capacity_bits//8} bytes")
        except Exception as e:
            self.cover_capacity_label.config(text=f"Error: {str(e)}")

    def enable_if_ready(self):
        if self.secret_file_path and self.cover_file_path:
            self.next_button.config(state=tk.NORMAL)
        else:
            self.next_button.config(state=tk.DISABLED)

    def check_capacity_and_ask(self):
        try:
            params, frames = get_wave_params(self.cover_file_path)
            if params.sampwidth!=2:
                messagebox.showerror("Error", "Cover must be 16-bit PCM")
                return
            total_samples = len(frames)//2
            capacity_bits = total_samples
            secret_size = os.path.getsize(self.secret_file_path)
            overhead = 200*8
            if secret_size*8+overhead>capacity_bits:
                messagebox.showerror("Error", "Secret file too large.")
                return
            self.pack_forget()
            detail_frame = EmbedDetailsFrame(self.parent, self, self.secret_file_path, self.cover_file_path)
            detail_frame.pack(padx=20, pady=20)
        except Exception as e:
            messagebox.showerror("Error", str(e))

class EmbedDetailsFrame(tk.Frame):
    def __init__(self, parent, prev_frame, secret_path, cover_path):
        super().__init__(parent)
        self.parent = parent
        self.prev_frame = prev_frame
        self.secret_path = secret_path
        self.cover_path = cover_path

        self.encryption_var = tk.BooleanVar(value=False)
        self.encryption_key_var = tk.StringVar()

        self.random_var = tk.BooleanVar(value=False)
        self.random_key_var = tk.StringVar()

        tk.Label(self, text="Additional Options", font=("Arial",16,"bold"))\
            .grid(row=0, column=0, columnspan=4, pady=10)

        tk.Label(self, text="Encrypt with Vigenère?", font=("Arial",12))\
            .grid(row=1, column=0, sticky="w")
        tk.Checkbutton(self, text="Enable Encryption", variable=self.encryption_var, command=self.toggle_encryption).grid(row=1, column=1, sticky="w")

        self.enc_label = tk.Label(self, text="Encryption Key (3-25 alpha)", font=("Arial",10))
        self.enc_entry = tk.Entry(self, textvariable=self.encryption_key_var, width=25)

        tk.Label(self, text="Stego Method:", font=("Arial",12))\
            .grid(row=2, column=0, sticky="w", pady=(15,0))
        tk.Radiobutton(self, text="Sequential", variable=self.random_var, value=False, command=self.toggle_random).grid(row=2, column=1, sticky="w")
        tk.Radiobutton(self, text="Random", variable=self.random_var, value=True, command=self.toggle_random).grid(row=2, column=2, sticky="w")

        self.rand_label = tk.Label(self, text="Random Key (3-25 alpha)", font=("Arial",10))
        self.rand_entry = tk.Entry(self, textvariable=self.random_key_var, width=25)

        tk.Button(self, text="Embed", command=self.do_embed).grid(row=3, column=0, padx=5, pady=20, sticky="w")
        tk.Button(self, text="Back", command=self.go_back).grid(row=3, column=1, padx=5, pady=20, sticky="w")

        self.saved_stego_path = None

    def go_back(self):
        self.pack_forget()
        self.prev_frame.pack(padx=20, pady=20)

    def toggle_encryption(self):
        if self.encryption_var.get():
            self.enc_label.grid(row=1, column=2, sticky="w")
            self.enc_entry.grid(row=1, column=3, sticky="w")
        else:
            self.enc_label.grid_remove()
            self.enc_entry.grid_remove()

    def toggle_random(self):
        if self.random_var.get():
            self.rand_label.grid(row=2, column=3, sticky="w")
            self.rand_entry.grid(row=2, column=4, sticky="w")
        else:
            self.rand_label.grid_remove()
            self.rand_entry.grid_remove()

    def do_embed(self):
        enc_bool = self.encryption_var.get()
        rand_bool = self.random_var.get()
        enc_key = self.encryption_key_var.get().strip()
        rand_key = self.random_key_var.get().strip()

        if enc_bool:
            if not (3<=len(enc_key)<=25 and enc_key.isalpha()):
                messagebox.showerror("Error", "Encryption key must be 3-25 alpha.")
                return
        else:
            enc_key = ""

        if rand_bool:
            if enc_bool:
                # re-use enc_key
                seed_key = enc_key
            else:
                if not (3<=len(rand_key)<=25 and rand_key.isalpha()):
                    messagebox.showerror("Error", "Random key must be 3-25 alpha.")
                    return
                seed_key = rand_key
        else:
            seed_key = None

        with open(self.secret_path, 'rb') as f:
            secret_data = f.read()
        if enc_bool:
            b64 = base64.b64encode(secret_data).decode('ascii')
            crypted = vigenere_encrypt(b64, enc_key)
            final_secret = crypted
        else:
            final_secret = secret_data

        file_name = os.path.splitext(os.path.basename(self.secret_path))[0]
        extension = os.path.splitext(self.secret_path)[1].replace('.', '')

        header = build_header(file_name, extension, enc_bool, rand_bool, len(final_secret))

        try:
            embed(
                cover_path=self.cover_path,
                out_path="embedded_temp.wav",
                header_data=header,
                secret_data=final_secret,
                randomize=rand_bool,
                seed=seed_key
            )
            psnr_val = compute_psnr(self.cover_path, "embedded_temp.wav")
            sp = filedialog.asksaveasfilename(
                defaultextension=".wav",
                filetypes=[("WAV", "*.wav")],
                title="Save Embedded Audio"
            )
            if sp:
                os.rename("embedded_temp.wav", sp)
                self.saved_stego_path = sp
                messagebox.showinfo("Success", f"Embedded!\nPSNR={psnr_val:.2f} dB\nSaved={sp}")

                # Now show the play buttons
                self.show_play_buttons()
            else:
                os.remove("embedded_temp.wav")
                messagebox.showinfo("Canceled", "No file saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def show_play_buttons(self):
        play_window = tk.Toplevel(self)
        play_window.title("Play Audio")

        tk.Label(play_window, text="Would you like to play the audio files?", font=("Arial", 12)).pack(padx=10, pady=10)

        def play_original():
            if self.cover_path:
                play_audio(self.cover_path)

        def play_stego():
            if self.saved_stego_path:
                play_audio(self.saved_stego_path)

        tk.Button(play_window, text="Play Original Cover", command=play_original).pack(pady=5)
        tk.Button(play_window, text="Play Stego Audio", command=play_stego).pack(pady=5)

class ExtractFrame(tk.Frame):
    def __init__(self, parent, menu_frame):
        super().__init__(parent)
        self.parent = parent
        self.menu_frame = menu_frame
        self.stego_file_path = None

        tk.Label(self, text="Extract Data from Audio", font=("Arial",16,"bold"))\
            .grid(row=0, column=0, columnspan=2, pady=10)

        tk.Button(self, text="Select Stego .WAV", command=self.select_stego).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.stego_label = tk.Label(self, text="No file selected")
        self.stego_label.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.extract_button = tk.Button(self, text="Extract", state=tk.DISABLED, command=self.do_extract)
        self.extract_button.grid(row=2, column=0, padx=5, pady=10, sticky="w")
        tk.Button(self, text="Back", command=lambda: parent.back_to_menu(self)).grid(row=2, column=1, padx=5, pady=10, sticky="w")

    def select_stego(self):
        f = filedialog.askopenfilename(title="Select Stego Audio", filetypes=[("WAV", "*.wav")])
        if f:
            self.stego_file_path = f
            self.stego_label.config(text=os.path.basename(f))
            self.extract_button.config(state=tk.NORMAL)

    def do_extract(self):
        if not self.stego_file_path:
            return
        try:
          
            header_guess_size = 200  # max possible header bytes

            params, frames = get_wave_params(self.stego_file_path)
            if params.sampwidth!=2:
                raise ValueError("Stego must be 16-bit PCM.")
            samples = []
            for i in range(0, len(frames), 2):
                val = frames[i] | (frames[i+1]<<8)
                samples.append(val)

            if header_guess_size*8>len(samples):
                raise ValueError("Not enough samples for header.")

            guess_bits = header_guess_size*8
            bitvals = []
            for i in range(guess_bits):
                bitvals.append(samples[i]&1)
            guess_data = bytearray()
            for i in range(0, guess_bits, 8):
                val=0
                for b in range(8):
                    val |= (bitvals[i+b]<<b)
                guess_data.append(val)

            fn, ext, ebool, rbool, dlen = parse_header(guess_data)
            actual_header = build_header(fn, ext, ebool, rbool, dlen)
            actual_header_size = len(actual_header)

            seed_key=None
            dec_key=None

            if rbool and ebool:
                t = self.prompt_for_key("File is RANDOM + ENCRYPTED. Enter single key:")
                if not t: return
                seed_key = t
                dec_key = t
            elif rbool and not ebool:
                t = self.prompt_for_key("File is RANDOM. Enter random key:")
                if not t: return
                seed_key=t
                dec_key=None
            elif (not rbool) and ebool:
                t = self.prompt_for_key("File is ENCRYPTED. Enter encryption key:")
                if not t: return
                seed_key=None
                dec_key=t
            else:
                seed_key=None
                dec_key=None

            hbytes, sbytes = extract(
                stego_path=self.stego_file_path,
                header_size=actual_header_size,
                secret_size=dlen,
                randomize=rbool,
                seed=seed_key
            )

            fn2, ext2, e2, r2, d2 = parse_header(hbytes)
            if e2!=ebool or r2!=rbool or d2!=dlen:
                messagebox.showwarning("Warning", "Header mismatch.")

            secret_data = sbytes
            if e2:
                if not dec_key:
                    raise ValueError("No key for decryption.")
                dec = vigenere_decrypt(secret_data, dec_key)
                dec_final = base64.b64decode(dec)
                secret_data = dec_final

            suggested_name = fn2 if fn2 else "extracted"
            if ext2:
                suggested_name += "."+ext2

            sp = filedialog.asksaveasfilename(initialfile=suggested_name, filetypes=[(ext2, f"*.{ext2}"), ("All", "*.*")], title="Save Extracted File")
            if sp:
                base, user_ext = os.path.splitext(sp)
                if not user_ext and ext2:
                    sp = sp + "." + ext2

                with open(sp,"wb") as f:
                    f.write(secret_data)
                messagebox.showinfo("Success", f"Extracted: {sp}")
            else:
                messagebox.showinfo("Canceled", "No file saved.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def prompt_for_key(self, msg):
        win = tk.Toplevel(self)
        win.title("Enter Key")
        tk.Label(win, text=msg).pack(padx=10, pady=10)
        var = tk.StringVar()
        ent = tk.Entry(win, textvariable=var, width=30)
        ent.pack(padx=10, pady=5)

        res = {"ok":False}

        def on_ok():
            k = var.get().strip()
            if not (3<=len(k)<=25 and k.isalpha()):
                messagebox.showerror("Error", "Key must be 3-25 alpha.")
                return
            res["ok"] = True
            win.destroy()

        tk.Button(win, text="OK", command=on_ok).pack(pady=10)
        win.grab_set()
        win.wait_window()
        if res["ok"]:
            return var.get().strip()
        return None

# ===== Main =====
if __name__=="__main__":
    app = AudioStegoApp()
    app.mainloop()
