import sys
import os
import wave
import random
import math
import base64
import subprocess
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QPushButton, 
                            QLabel, QVBoxLayout, QHBoxLayout, QGridLayout,
                            QFileDialog, QMessageBox, QCheckBox, QRadioButton,
                            QLineEdit, QGroupBox, QDialog, QProgressBar, QFrame,
                            QSplitter, QTabWidget)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QIcon, QPixmap

# ===== Audio Player =====
def play_audio(path):
    if sys.platform.startswith('win'): # Windows
        os.startfile(path)
    elif sys.platform.startswith('darwin'): # MacOS
        subprocess.call(['open', path])
    else: # Linux-based
        subprocess.call(['xdg-open', path])

def quantization_embed(cover_path, out_path, header_data, secret_data, interval, offset_div):
    params, frames = get_wave_params(cover_path)
    n_channels, sampwidth, framerate, n_frames, comp_type, comp_name = params

    if sampwidth != 2:
        raise ValueError("Cover WAV must be 16-bit PCM.")

    samples = []
    for i in range(0, len(frames), 2):
        sample = frames[i] | (frames[i + 1] << 8)
        samples.append(sample)

    header_bits = [((byte >> bit_i) & 1) for byte in header_data for bit_i in range(8)]
    secret_bits = [((byte >> bit_i) & 1) for byte in secret_data for bit_i in range(8)]
    all_bits = header_bits + secret_bits

    if len(all_bits) > len(samples):
        raise ValueError("Not enough capacity for quantization embedding.")

    embedded_samples = []
    for i, bit in enumerate(all_bits):
        x = samples[i]
        Q = interval * round(x / interval)
        y = Q + interval // offset_div if bit else Q - interval // offset_div
        y = max(0, min(65535, y))
        embedded_samples.append(y)
    embedded_samples += samples[len(all_bits):]

    new_frames = bytearray()
    for s in embedded_samples:
        new_frames.append(s & 0xFF)
        new_frames.append((s >> 8) & 0xFF)

    save_wave_file(out_path, params, new_frames)

def quantization_extract(stego_path, header_size, secret_size, interval, offset_div):
    params, frames = get_wave_params(stego_path)
    n_channels, sampwidth, framerate, n_frames, comp_type, comp_name = params

    if sampwidth != 2:
        raise ValueError("Stego WAV must be 16-bit PCM.")

    samples = []
    for i in range(0, len(frames), 2):
        sample = frames[i] | (frames[i + 1] << 8)
        samples.append(sample)

    total_bits = (header_size + secret_size) * 8
    if total_bits > len(samples):
        raise ValueError("Not enough capacity for quantization extraction.")

    extracted_bits = []
    for i in range(total_bits):
        x = samples[i]
        Q = interval * round(x / interval)
        diff = x - Q
        extracted_bits.append(1 if diff >= 0 else 0)

    header_bits = extracted_bits[:header_size * 8]
    secret_bits = extracted_bits[header_size * 8:]

    header_bytes = bytearray()
    for i in range(0, len(header_bits), 8):
        val = sum((header_bits[i + b] << b) for b in range(8))
        header_bytes.append(val)

    secret_bytes = bytearray()
    for i in range(0, len(secret_bits), 8):
        val = sum((secret_bits[i + b] << b) for b in range(8))
        secret_bytes.append(val)

    return bytes(header_bytes), bytes(secret_bytes)

# ===== Encryption =====
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

    params, frames = get_wave_params(cover_path)
    n_channels, sampwidth, framerate, n_frames, comp_type, comp_name = params
    
    if sampwidth != 2: # 2 sampwidth = 16-bit PCM
        raise ValueError("Cover WAV must be 16-bit PCM.") # 16-bit PCM only

    samples = []
    
    # Convert byte frames to samples
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
        s = s & 0xFFFE  #
        s |= bit_val    
        samples[i] = s

    # 2) Embed secret data in the remaining samples
    secret_bits = []
    for byte_val in secret_data:
        for bit_i in range(8):
            secret_bits.append((byte_val >> bit_i) & 1)

    # Determine indices for secret bits (sequential or random)
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

    # Convert samples back to frames
    new_frames = bytearray()
    for s in samples:
        new_frames.append(s & 0xFF)
        new_frames.append((s >> 8) & 0xFF)

    # Save the new WAV file
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

    # Extract header bits (always sequential)
    header_bits = []
    for i in range(header_len_bits):
        header_bits.append(samples[i] & 1) 
        
    # Convert header bits to bytes
    header_bytes = bytearray()
    for i in range(0, header_len_bits, 8):
        val = 0
        for b in range(8):
            val |= (header_bits[i+b] << b)
        header_bytes.append(val)

    # Determine indices for secret bits (sequential or random)
    secret_indices = list(range(header_len_bits, header_len_bits + secret_len_bits))
    if randomize and seed:
        random.seed(seed)
        random.shuffle(secret_indices)

    # Extract secret bits
    secret_bits = []
    for i in range(secret_len_bits):
        idx = secret_indices[i]
        secret_bits.append(samples[idx] & 1)  

    # Convert secret bits to bytes
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

    # Calculate Mean Square Error
    mse = 0.0
    for osmp, ssmp in zip(orig_samples, stego_samples):
        diff = (osmp - ssmp)
        mse += diff * diff
    mse /= len(orig_samples)

    if mse == 0:
        return 999.99
    
    # Calculate PSNR
    max_val = 32767  # Max value for 16-bit audio
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

    # Read filename length and filename
    fn_len = bytes_to_int(read_bytes(4))
    fn = read_bytes(fn_len).decode('utf-8', errors='ignore')

    # Read extension length and extension
    ext_len = bytes_to_int(read_bytes(4))
    ext = read_bytes(ext_len).decode('utf-8', errors='ignore')

    # Read encryption flag
    enc_b = read_bytes(1)
    enc_bool = (enc_b[0] == 1)

    # Read randomization flag
    rand_b = read_bytes(1)
    rand_bool = (rand_b[0] == 1)

    # Read data length
    d_len = bytes_to_int(read_bytes(4))

    return fn, ext, enc_bool, rand_bool, d_len

# ===== Main GUI =====
class AudioStegoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Audio Stegosaurus")
        self.setMinimumSize(800, 600)
        
        # Create tab widget for main/extract operations
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.home_tab = HomeTab(self)
        self.embed_tab = EmbedTab(self)
        self.extract_tab = ExtractTab(self)
        
        # Add tabs
        self.tabs.addTab(self.home_tab, "Home")
        self.tabs.addTab(self.embed_tab, "Embed")
        self.tabs.addTab(self.extract_tab, "Extract")
        
        # Global stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-top: 2px solid #0078d7;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QGroupBox {
                border: 1px solid #cccccc;
                border-radius: 4px;
                margin-top: 15px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                padding: 0 5px;
            }
            QLineEdit {
                padding: 6px;
                border: 1px solid #aaaaaa;
                border-radius: 3px;
            }
            QCheckBox, QRadioButton {
                spacing: 8px;
            }
        """)

class HomeTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        # Title and description
        title_label = QLabel("Audio Stegosaurus")
        title_label.setFont(QFont("Arial", 24, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        desc_label = QLabel("Hide secret files within audio WAV files using LSB steganography!")
        desc_label.setFont(QFont("Arial", 14))
        desc_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc_label)
        
        # Information section
        info_frame = QFrame()
        info_frame.setFrameShape(QFrame.StyledPanel)
        info_frame.setStyleSheet("background-color: #f0f8ff; padding: 15px; border-radius: 5px;")
        info_layout = QVBoxLayout(info_frame)
        
        info_title = QLabel("About LSB Audio Steganography")
        info_title.setFont(QFont("Arial", 14, QFont.Bold))
        info_layout.addWidget(info_title)
        
        info_text = QLabel(
            "LSB (Least Significant Bit) steganography is a technique for hiding information "
            "by replacing the least significant bit of each sample in an audio file. "
            "This application allows you to embed any file into a WAV audio file and "
            "later extract it without noticeable quality loss."
        )
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        features_title = QLabel("Features:")
        features_title.setFont(QFont("Arial", 12, QFont.Bold))
        info_layout.addWidget(features_title)
        
        features_text = QLabel(
            "• Embed any file type into WAV audio files\n"
            "• Vigenère encryption for additional security\n"
            "• Sequential or randomized bit embedding\n"
            "• PSNR calculation to measure audio quality impact\n"
            "• Header system to store metadata about hidden content"
        )
        info_layout.addWidget(features_text)
        
        layout.addWidget(info_frame)
        
        # Quick start buttons
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(20)
        
        embed_container = QVBoxLayout()
        embed_btn = QPushButton("Embed Data")
        embed_btn.setMinimumSize(200, 60)
        embed_btn.setFont(QFont("Arial", 14))
        embed_btn.clicked.connect(lambda: parent.tabs.setCurrentIndex(1))
        embed_container.addWidget(embed_btn)
        
        embed_desc = QLabel("Hide a file in audio")
        embed_desc.setAlignment(Qt.AlignCenter)
        embed_container.addWidget(embed_desc)
        
        extract_container = QVBoxLayout()
        extract_btn = QPushButton("Extract Data")
        extract_btn.setMinimumSize(200, 60)
        extract_btn.setFont(QFont("Arial", 14))
        extract_btn.clicked.connect(lambda: parent.tabs.setCurrentIndex(2))
        extract_container.addWidget(extract_btn)
        
        extract_desc = QLabel("Retrieve hidden files")
        extract_desc.setAlignment(Qt.AlignCenter)
        extract_container.addWidget(extract_desc)
        
        buttons_layout.addLayout(embed_container)
        buttons_layout.addLayout(extract_container)
        layout.addLayout(buttons_layout)

class EmbedTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.secret_file_path = None
        self.cover_file_path = None
        self.saved_stego_path = None
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Title
        title_label = QLabel("Your Secret is Safe with Us!")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Step 1: File Selection
        file_group = QGroupBox("Step 1: File Selection")
        file_layout = QGridLayout(file_group)
        
        # Secret file selection
        secret_btn = QPushButton("Select Secret File")
        secret_btn.clicked.connect(self.select_secret_file)
        file_layout.addWidget(secret_btn, 0, 0)
        
        self.secret_label = QLabel("No file selected")
        self.secret_label.setStyleSheet("padding: 8px; background-color: #f5f5f5; border: 1px solid #cccccc;")
        file_layout.addWidget(self.secret_label, 0, 1, 1, 2)
        
        # Cover file selection
        cover_btn = QPushButton("Select Cover WAV")
        cover_btn.clicked.connect(self.select_cover_file)
        file_layout.addWidget(cover_btn, 1, 0)
        
        self.cover_label = QLabel("No file selected")
        self.cover_label.setStyleSheet("padding: 8px; background-color: #f5f5f5; border: 1px solid #cccccc;")
        file_layout.addWidget(self.cover_label, 1, 1)
        
        self.capacity_label = QLabel("Capacity: N/A")
        self.capacity_label.setStyleSheet("padding: 8px; font-weight: bold;")
        file_layout.addWidget(self.capacity_label, 1, 2)
        
        main_layout.addWidget(file_group)
        
        # Step 2: Options
        options_group = QGroupBox("Step 2: Steganography Options")
        options_layout = QVBoxLayout(options_group)
        
        # Encryption settings
        encryption_group = QGroupBox("Encryption")
        encryption_layout = QGridLayout(encryption_group)
        
        self.encryption_check = QCheckBox("Encrypt with Vigenère cipher")
        self.encryption_check.stateChanged.connect(self.toggle_encryption)
        encryption_layout.addWidget(self.encryption_check, 0, 0, 1, 2)
        
        self.encrypt_key_label = QLabel("Encryption Key (3-25 alpha):")
        self.encrypt_key_label.setVisible(False)
        encryption_layout.addWidget(self.encrypt_key_label, 1, 0)
        
        self.encrypt_key_input = QLineEdit()
        self.encrypt_key_input.setVisible(False)
        self.encrypt_key_input.setPlaceholderText("Enter encryption key")
        encryption_layout.addWidget(self.encrypt_key_input, 1, 1)
        
        options_layout.addWidget(encryption_group)
        
        # Steganography method settings
        stego_group = QGroupBox("Steganography Method")
        stego_layout = QGridLayout(stego_group)
        
        self.sequential_radio = QRadioButton("Sequential")
        self.sequential_radio.setChecked(True)
        self.sequential_radio.toggled.connect(self.toggle_random)
        stego_layout.addWidget(self.sequential_radio, 0, 0)
        
        self.random_radio = QRadioButton("Random (Shuffled)")
        self.random_radio.toggled.connect(self.toggle_random)
        stego_layout.addWidget(self.random_radio, 0, 1)
        
        self.random_key_label = QLabel("Random Key (3-25 alpha):")
        self.random_key_label.setVisible(False)
        stego_layout.addWidget(self.random_key_label, 1, 0)
        
        self.random_key_input = QLineEdit()
        self.random_key_input.setVisible(False)
        self.random_key_input.setPlaceholderText("Enter random key")
        stego_layout.addWidget(self.random_key_input, 1, 1)
        
        options_layout.addWidget(stego_group)
        # === Tambahan untuk metode Quantization ===
        method_group = QGroupBox("Embedding Method")
        method_layout = QHBoxLayout(method_group)
        self.method_lsb = QRadioButton("LSB")
        self.method_quant = QRadioButton("Quantization")
        self.method_lsb.setChecked(True)
        method_layout.addWidget(self.method_lsb)
        method_layout.addWidget(self.method_quant)
        options_layout.addWidget(method_group)

        quant_group = QGroupBox("Quantization Parameters")
        quant_layout = QGridLayout(quant_group)
        self.interval_label = QLabel("Interval:")
        self.interval_input = QLineEdit("512")
        self.offset_div_label = QLabel("Offset Divisor:")
        self.offset_div_input = QLineEdit("8")
        quant_layout.addWidget(self.interval_label, 0, 0)
        quant_layout.addWidget(self.interval_input, 0, 1)
        quant_layout.addWidget(self.offset_div_label, 1, 0)
        quant_layout.addWidget(self.offset_div_input, 1, 1)
        options_layout.addWidget(quant_group)

        self.method_lsb.toggled.connect(lambda checked: quant_group.setVisible(not checked))
        quant_group.setVisible(False)

        main_layout.addWidget(options_group)
        
        # Step 3: Process
        process_group = QGroupBox("Step 3: Process")
        process_layout = QHBoxLayout(process_group)
        
        self.embed_btn = QPushButton("Embed Data")
        self.embed_btn.setMinimumWidth(150)
        self.embed_btn.setEnabled(False)
        self.embed_btn.clicked.connect(self.do_embed)
        process_layout.addWidget(self.embed_btn)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        process_layout.addWidget(self.progress)
        
        main_layout.addWidget(process_group)
        
        # Results area
        self.results_group = QGroupBox("Results")
        self.results_group.setVisible(False)
        results_layout = QVBoxLayout(self.results_group)
        
        self.results_label = QLabel()
        self.results_label.setWordWrap(True)
        results_layout.addWidget(self.results_label)
        
        play_layout = QHBoxLayout()
        
        play_original_btn = QPushButton("Play Original Audio")
        play_original_btn.clicked.connect(self.play_original)
        play_layout.addWidget(play_original_btn)
        
        play_stego_btn = QPushButton("Play Stego Audio")
        play_stego_btn.clicked.connect(self.play_stego)
        play_layout.addWidget(play_stego_btn)
        
        results_layout.addLayout(play_layout)
        
        main_layout.addWidget(self.results_group)
        
        # Add stretch to push everything to the top
        main_layout.addStretch()
    
    def select_secret_file(self):
        """Select the secret file to embed"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Secret File", "", "All Files (*.*)")
        
        if file_path:
            self.secret_file_path = file_path
            self.secret_label.setText(os.path.basename(file_path))
            self.check_files_ready()
    
    def select_cover_file(self):
        """Select the cover WAV file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Cover Audio", "", "WAV Files (*.wav)")
        
        if file_path:
            self.cover_file_path = file_path
            self.cover_label.setText(os.path.basename(file_path))
            self.check_capacity()
            self.check_files_ready()
    
    def check_capacity(self):
        """Check the capacity of the cover file"""
        if not self.cover_file_path:
            return
        
        try:
            params, frames = get_wave_params(self.cover_file_path)
            if params[1] != 2:  # sampwidth
                self.capacity_label.setText("Error: Must be 16-bit PCM")
                self.capacity_label.setStyleSheet("color: red; font-weight: bold;")
                return
                
            total_samples = len(frames) // 2
            overhead_bits = 200 * 8  # Approximate header size
            capacity_bits = total_samples - overhead_bits
            capacity_bytes = capacity_bits // 8
            
            if capacity_bytes < 0:
                capacity_bytes = 0
                
            # Format capacity with commas and show KB/MB for large values
            if capacity_bytes > 1024 * 1024:
                capacity_str = f"{capacity_bytes / (1024 * 1024):.2f} MB"
            elif capacity_bytes > 1024:
                capacity_str = f"{capacity_bytes / 1024:.2f} KB"
            else:
                capacity_str = f"{capacity_bytes:,} bytes"
                
            self.capacity_label.setText(f"Capacity: ~{capacity_str}")
            self.capacity_label.setStyleSheet("color: green; font-weight: bold;")
        except Exception as e:
            self.capacity_label.setText(f"Error: {str(e)}")
            self.capacity_label.setStyleSheet("color: red; font-weight: bold;")
    
    def check_files_ready(self):
        """Check if both files are selected and enable the embed button"""
        if self.secret_file_path and self.cover_file_path:
            self.embed_btn.setEnabled(True)
        else:
            self.embed_btn.setEnabled(False)
    
    def toggle_encryption(self, state):
        """Toggle encryption options visibility"""
        is_checked = state == Qt.Checked
        self.encrypt_key_label.setVisible(is_checked)
        self.encrypt_key_input.setVisible(is_checked)
    
    def toggle_random(self, checked):
        """Toggle random key visibility based on radio button"""
        if checked and self.sender() == self.random_radio:
            self.random_key_label.setVisible(True)
            self.random_key_input.setVisible(True)
        else:
            self.random_key_label.setVisible(False)
            self.random_key_input.setVisible(False)
    
    def validate_keys(self):
        """Validate encryption and random keys"""
        enc_bool = self.encryption_check.isChecked()
        rand_bool = self.random_radio.isChecked()
        
        enc_key = self.encrypt_key_input.text().strip()
        rand_key = self.random_key_input.text().strip()
        
        if enc_bool and not (3 <= len(enc_key) <= 25 and enc_key.isalpha()):
            QMessageBox.warning(self, "Invalid Key", 
                               "Encryption key must be 3-25 alphabetic characters.")
            return False, None, None
        
        if rand_bool:
            if enc_bool:
                # Reuse encryption key for randomization
                seed_key = enc_key
            else:
                if not (3 <= len(rand_key) <= 25 and rand_key.isalpha()):
                    QMessageBox.warning(self, "Invalid Key", 
                                      "Random key must be 3-25 alphabetic characters.")
                    return False, None, None
                seed_key = rand_key
        else:
            seed_key = None
            
        return True, enc_key if enc_bool else "", seed_key
    
    def do_embed(self):
        """Perform the embedding process"""
        # Check if files exist
        if not os.path.exists(self.secret_file_path):
            QMessageBox.critical(self, "Error", "Secret file does not exist or was moved.")
            return
            
        if not os.path.exists(self.cover_file_path):
            QMessageBox.critical(self, "Error", "Cover file does not exist or was moved.")
            return
        
        # Validate keys
        valid, enc_key, seed_key = self.validate_keys()
        if not valid:
            return
            
        enc_bool = self.encryption_check.isChecked()
        rand_bool = self.random_radio.isChecked()
        
        # Read secret file
        try:
            with open(self.secret_file_path, 'rb') as f:
                secret_data = f.read()
                
            # Apply encryption if enabled
            if enc_bool:
                b64 = base64.b64encode(secret_data).decode('ascii')
                crypted = vigenere_encrypt(b64, enc_key)
                final_secret = crypted
            else:
                final_secret = secret_data
                
            # Get filename and extension
            file_name = os.path.splitext(os.path.basename(self.secret_file_path))[0]
            extension = os.path.splitext(self.secret_file_path)[1].replace('.', '')
            
            # Build header
            header = build_header(file_name, extension, enc_bool, rand_bool, len(final_secret))
            
            # Check capacity one more time
            secret_size = len(final_secret)
            header_size = len(header)
            total_size = (secret_size + header_size) * 8  # in bits
            
            params, frames = get_wave_params(self.cover_file_path)
            if params[1] != 2:  # sampwidth
                QMessageBox.critical(self, "Error", "Cover audio must be 16-bit PCM.")
                return
                
            total_samples = len(frames) // 2
            if total_size > total_samples:
                QMessageBox.critical(self, "Error", 
                                   f"Secret file too large for cover audio.\n"
                                   f"Required: {total_size} bits, Available: {total_samples} bits")
                return
            
            # Prepare for embedding
            temp_path = "embedded_temp.wav"
            
            # Update UI
            self.embed_btn.setEnabled(False)
            self.progress.setVisible(True)
            self.progress.setValue(20)
            
            # Embed data
            embed(
                cover_path=self.cover_file_path,
                out_path=temp_path,
                header_data=header,
                secret_data=final_secret,
                randomize=rand_bool,
                seed=seed_key
            )
            
            self.progress.setValue(70)
            
            # Calculate PSNR
            psnr_val = compute_psnr(self.cover_file_path, temp_path)
            
            self.progress.setValue(80)
            
            # Save file
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save Embedded Audio", "", "WAV Files (*.wav)")
            
            if save_path:
                if os.path.exists(temp_path):
                    # If there's already a file at save_path, remove it
                    if os.path.exists(save_path):
                        os.remove(save_path)
                    os.rename(temp_path, save_path)
                    
                    self.saved_stego_path = save_path
                    self.progress.setValue(100)
                    
                    # Display results
                    self.results_group.setVisible(True)
                    quality_text = ""
                    if psnr_val > 50:
                        quality_text = "Excellent quality, imperceptible changes"
                    elif psnr_val > 40:
                        quality_text = "Very good quality, minimal impact"
                    elif psnr_val > 30:
                        quality_text = "Good quality, slight impact possible"
                    else:
                        quality_text = "Fair quality, some impact may be noticeable"
                        
                    self.results_label.setText(
                        f"<b>Embedding Successful!</b><br><br>"
                        f"<b>PSNR:</b> {psnr_val:.2f} dB ({quality_text})<br>"
                        f"<b>File size:</b> {os.path.getsize(save_path) / 1024:.2f} KB<br>"
                        f"<b>Hidden data:</b> {secret_size / 1024:.2f} KB<br>"
                        f"<b>Security:</b> {'Encrypted' if enc_bool else 'Not encrypted'}, "
                        f"{'Randomized' if rand_bool else 'Sequential'} embedding<br>"
                        f"<b>Saved to:</b> {save_path}"
                    )
                    
                    QMessageBox.information(self, "Success", "Data successfully embedded!")
            else:
                # User canceled the save dialog
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                QMessageBox.information(self, "Canceled", "Operation canceled. No file saved.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during embedding: {str(e)}")
            if os.path.exists("embedded_temp.wav"):
                os.remove("embedded_temp.wav")
        
        finally:
            self.embed_btn.setEnabled(True)
            self.progress.setVisible(False)
    
    def play_original(self):
        """Play the original audio file"""
        if self.cover_file_path and os.path.exists(self.cover_file_path):
            play_audio(self.cover_file_path)
        else:
            QMessageBox.warning(self, "Error", "Original audio file not found")
    
    def play_stego(self):
        """Play the stego audio file"""
        if self.saved_stego_path and os.path.exists(self.saved_stego_path):
            play_audio(self.saved_stego_path)
        else:
            QMessageBox.warning(self, "Error", "Stego audio file not found")

class ExtractTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.stego_file_path = None
        
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        
        # Title
        title_label = QLabel("Extract Data from a Stego-Audio")
        title_label.setFont(QFont("Arial", 18, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Step 1: File Selection
        file_group = QGroupBox("Step 1: Select Stego Audio")
        file_layout = QHBoxLayout(file_group)
        
        stego_btn = QPushButton("Select Stego WAV")
        stego_btn.clicked.connect(self.select_stego_file)
        file_layout.addWidget(stego_btn)
        
        self.stego_label = QLabel("No file selected")
        self.stego_label.setStyleSheet("padding: 8px; background-color: #f5f5f5; border: 1px solid #cccccc;")
        file_layout.addWidget(self.stego_label)
        
        main_layout.addWidget(file_group)
        
        # Step 2: Process
        process_group = QGroupBox("Step 2: Extract Data")
        process_layout = QHBoxLayout(process_group)
        
        self.extract_btn = QPushButton("Extract Data")
        self.extract_btn.setMinimumWidth(150)
        self.extract_btn.setEnabled(False)
        self.extract_btn.clicked.connect(self.do_extract)
        process_layout.addWidget(self.extract_btn)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        process_layout.addWidget(self.progress)
        
        main_layout.addWidget(process_group)
        
        # Results area
        self.results_group = QGroupBox("Extraction Results")
        self.results_group.setVisible(False)
        results_layout = QVBoxLayout(self.results_group)
        
        self.results_label = QLabel()
        self.results_label.setWordWrap(True)
        results_layout.addWidget(self.results_label)
        
        self.play_stego_btn = QPushButton("Play Stego Audio")
        self.play_stego_btn.clicked.connect(self.play_stego)
        results_layout.addWidget(self.play_stego_btn)
        
        main_layout.addWidget(self.results_group)
        
        # Add stretch to push everything to the top
        main_layout.addStretch()
    
    def select_stego_file(self):
        """Select the stego WAV file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Audio", "", "WAV Files (*.wav)")
        
        if file_path:
            self.stego_file_path = file_path
            self.stego_label.setText(os.path.basename(file_path))
            self.extract_btn.setEnabled(True)
            
            # Hide the results section when selecting a new file
            self.results_group.setVisible(False)
    
    def do_extract(self):
        """Perform the extraction process"""
        if not self.stego_file_path or not os.path.exists(self.stego_file_path):
            QMessageBox.critical(self, "Error", "Stego file does not exist or was moved.")
            return
        
        try:
            # Update UI
            self.extract_btn.setEnabled(False)
            self.progress.setVisible(True)
            self.progress.setValue(10)
            
            # Check if it's a valid 16-bit PCM WAV file
            params, frames = get_wave_params(self.stego_file_path)
            if params[1] != 2:  # sampwidth
                QMessageBox.critical(self, "Error", "Stego audio must be 16-bit PCM.")
                return
                
            # Estimate header size for initial extraction
            header_guess_size = 200  # Max possible header bytes
            
            # Extract sample bits for header guess
            samples = []
            for i in range(0, len(frames), 2):
                val = frames[i] | (frames[i+1] << 8)
                samples.append(val)
                
            guess_bits = header_guess_size * 8
            if guess_bits > len(samples):
                QMessageBox.critical(self, "Error", "Not enough samples for header.")
                return
                
            self.progress.setValue(20)
            
            # Extract bits for header estimation
            bitvals = []
            for i in range(guess_bits):
                bitvals.append(samples[i] & 1)
                
            guess_data = bytearray()
            for i in range(0, guess_bits, 8):
                val = 0
                for b in range(8):
                    val |= (bitvals[i+b] << b)
                guess_data.append(val)
                
            self.progress.setValue(30)
            
            # Parse header
            try:
                fn, ext, ebool, rbool, dlen = parse_header(guess_data)
                actual_header = build_header(fn, ext, ebool, rbool, dlen)
                actual_header_size = len(actual_header)
            except Exception as e:
                QMessageBox.critical(self, "Error", 
                                   f"Failed to parse header. This may not be a valid stego file.\nError: {str(e)}")
                return
                
            self.progress.setValue(40)
            
            # Get keys if needed
            seed_key = None
            dec_key = None
            
            if rbool and ebool:
                # Both random and encrypted
                key, ok = self.prompt_for_key("File is RANDOM + ENCRYPTED", 
                                             "This file uses both randomization and encryption with the same key.")
                if ok and key:
                    seed_key = key
                    dec_key = key
                else:
                    return
            elif rbool and not ebool:
                # Random only
                key, ok = self.prompt_for_key("Random Key Required", 
                                             "This file uses randomized bit embedding.")
                if ok and key:
                    seed_key = key
                else:
                    return
            elif (not rbool) and ebool:
                # Encrypted only
                key, ok = self.prompt_for_key("Encryption Key Required", 
                                             "This file is encrypted.")
                if ok and key:
                    dec_key = key
                else:
                    return
                    
            self.progress.setValue(50)
            
            # Extract data
            hbytes, sbytes = extract(
                stego_path=self.stego_file_path,
                header_size=actual_header_size,
                secret_size=dlen,
                randomize=rbool,
                seed=seed_key
            )
            
            self.progress.setValue(70)
            
            # Verify header
            try:
                fn2, ext2, e2, r2, d2 = parse_header(hbytes)
                if e2 != ebool or r2 != rbool or d2 != dlen:
                    QMessageBox.warning(self, "Warning", 
                                      "Header verification failed. Data may be corrupted.")
            except:
                QMessageBox.warning(self, "Warning", 
                                  "Header verification failed. Data may be corrupted.")
            
            # Process the extracted data
            secret_data = sbytes
            if e2:
                if not dec_key:
                    QMessageBox.critical(self, "Error", "No key provided for decryption.")
                    return
                    
                try:
                    dec = vigenere_decrypt(secret_data, dec_key)
                    dec_final = base64.b64decode(dec)
                    secret_data = dec_final
                except Exception as e:
                    QMessageBox.critical(self, "Decryption Error", 
                                       f"Failed to decrypt data. The key may be incorrect.\nError: {str(e)}")
                    return
            
            self.progress.setValue(80)
            
            # Save the extracted file
            suggested_name = fn2 if fn2 else "extracted"
            if ext2:
                suggested_name += "." + ext2
                
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save Extracted File", suggested_name, 
                f"{ext2.upper() if ext2 else 'All'} Files ({'*.' + ext2 if ext2 else '*.*'})")
            
            if save_path:
                # Add extension if user didn't specify one and we know it
                base, user_ext = os.path.splitext(save_path)
                if not user_ext and ext2:
                    save_path = save_path + "." + ext2
                    
                with open(save_path, "wb") as f:
                    f.write(secret_data)
                    
                self.progress.setValue(100)
                
                # Display results
                self.results_group.setVisible(True)
                self.results_label.setText(
                    f"<b>Extraction Successful!</b><br><br>"
                    f"<b>Filename:</b> {fn2 if fn2 else 'Unknown'}<br>"
                    f"<b>File type:</b> {ext2 if ext2 else 'Unknown'}<br>"
                    f"<b>Security:</b> {'Encrypted' if e2 else 'Not encrypted'}, "
                    f"{'Randomized' if r2 else 'Sequential'} embedding<br>"
                    f"<b>Data size:</b> {len(secret_data) / 1024:.2f} KB<br>"
                    f"<b>Saved to:</b> {save_path}"
                )
                
                QMessageBox.information(self, "Success", "Data successfully extracted!")
            else:
                QMessageBox.information(self, "Canceled", "Operation canceled. No file saved.")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error during extraction: {str(e)}")
        
        finally:
            self.extract_btn.setEnabled(True)
            self.progress.setVisible(False)
    
    def prompt_for_key(self, title, message):
        """Prompt user for an encryption or randomization key"""
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout(dialog)
        
        # Add message label
        msg_label = QLabel(message)
        msg_label.setWordWrap(True)
        layout.addWidget(msg_label)
        
        # Key input field
        key_label = QLabel("Enter key (3-25 alphabetic characters):")
        layout.addWidget(key_label)
        
        key_input = QLineEdit()
        key_input.setPlaceholderText("Enter key")
        layout.addWidget(key_input)
        
        # Error label
        error_label = QLabel()
        error_label.setStyleSheet("color: red;")
        error_label.setVisible(False)
        layout.addWidget(error_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)
        
        # Connect buttons
        ok_button.clicked.connect(lambda: self.validate_dialog_key(dialog, key_input, error_label))
        cancel_button.clicked.connect(dialog.reject)
        
        # Show dialog
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            return key_input.text().strip(), True
        else:
            return None, False
    
    def validate_dialog_key(self, dialog, key_input, error_label):
        """Validate the key input in the dialog"""
        key = key_input.text().strip()
        
        if not (3 <= len(key) <= 25 and key.isalpha()):
            error_label.setText("Key must be 3-25 alphabetic characters.")
            error_label.setVisible(True)
            return
            
        dialog.accept()
    
    def play_stego(self):
        """Play the stego audio file"""
        if self.stego_file_path and os.path.exists(self.stego_file_path):
            play_audio(self.stego_file_path)
        else:
            QMessageBox.warning(self, "Error", "Stego audio file not found")

# ===== Main =====
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a consistent look
    window = AudioStegoApp()
    window.show()
    sys.exit(app.exec_())