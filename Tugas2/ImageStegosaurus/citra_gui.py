import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from lsb import encode_lsb, decode_lsb, calculate_psnr
from bpcs import encode_bpcs, decode_bpcs

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Tool")
        self.root.geometry("800x620")
        self.root.configure(bg="#f0f0f0")
        
        # Variables
        self.cover_path = tk.StringVar()
        self.message_path = tk.StringVar()
        self.stego_path = tk.StringVar(value="stego_output.png")
        self.extraction_path = tk.StringVar(value="extracted_file")
        self.stego_key = tk.StringVar()
        self.encryption_type = tk.StringVar(value="none")
        self.is_sequential = tk.BooleanVar(value=True)
        self.method = tk.StringVar(value="lsb")
        self.threshold = tk.DoubleVar(value=0.3)
        
        # Create directories if they don't exist
        os.makedirs("stego", exist_ok=True)
        os.makedirs("extraction", exist_ok=True)
        os.makedirs("media", exist_ok=True)
        
        # Create main frame
        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        tab_control = ttk.Notebook(main_frame)
        
        # Embedding tab
        embed_tab = ttk.Frame(tab_control)
        tab_control.add(embed_tab, text="Embed Message")
        
        # Extraction tab
        extract_tab = ttk.Frame(tab_control)
        tab_control.add(extract_tab, text="Extract Message")
        
        tab_control.pack(expand=1, fill="both")
        
        # Embedding tab content
        self.setup_embed_tab(embed_tab)
        
        # Extraction tab content
        self.setup_extract_tab(extract_tab)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Set initial status
        self.status_var.set("Ready")
        
        # Image windows
        self.original_window = None
        self.stego_window = None

    def setup_embed_tab(self, parent):
        # Create frames
        input_frame = ttk.LabelFrame(parent, text="Input Files", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        options_frame = ttk.LabelFrame(parent, text="Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        button_frame = ttk.Frame(parent, padding=10)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Input fields
        ttk.Label(input_frame, text="Cover Image:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.cover_path, width=50).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_cover).grid(column=2, row=0, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Message File:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.message_path, width=50).grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_message).grid(column=2, row=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Stego Output:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.stego_path, width=50).grid(column=1, row=2, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_stego_output).grid(column=2, row=2, padx=5, pady=5)
        
        # Options
        ttk.Label(options_frame, text="Method:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo = ttk.Combobox(options_frame, textvariable=self.method, state="readonly")
        method_combo['values'] = ('lsb', 'bpcs')
        method_combo.grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo.bind('<<ComboboxSelected>>', self.update_options_visibility)
        
        # Encryption options
        ttk.Label(options_frame, text="Encrypt message?").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        encrypt_frame = ttk.Frame(options_frame)
        encrypt_frame.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        self.encrypt_yes = ttk.Radiobutton(encrypt_frame, text="Yes", variable=self.encryption_type, value="vigenere", command=self.update_key_visibility)
        self.encrypt_no = ttk.Radiobutton(encrypt_frame, text="No", variable=self.encryption_type, value="none", command=self.update_key_visibility)
        self.encrypt_yes.pack(side=tk.LEFT, padx=5)
        self.encrypt_no.pack(side=tk.LEFT, padx=5)
        self.encrypt_no.invoke()  # Default to "No"
        
        # Key input
        self.key_label = ttk.Label(options_frame, text="Enter secret key (max 25 chars):")
        self.key_label.grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        self.key_entry = ttk.Entry(options_frame, textvariable=self.stego_key, width=30, show="*")
        self.key_entry.grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide key fields
        self.key_label.grid_remove()
        self.key_entry.grid_remove()
        
        # Method-specific options
        # LSB options
        self.lsb_frame = ttk.Frame(options_frame)
        self.lsb_frame.grid(column=0, row=3, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.lsb_frame, text="Use sequential embedding?").pack(side=tk.LEFT, padx=5)
        self.seq_yes = ttk.Radiobutton(self.lsb_frame, text="Yes", variable=self.is_sequential, value=True, command=self.update_sequential_state)
        self.seq_no = ttk.Radiobutton(self.lsb_frame, text="No", variable=self.is_sequential, value=False, command=self.update_sequential_state)
        self.seq_yes.pack(side=tk.LEFT, padx=5)
        self.seq_no.pack(side=tk.LEFT, padx=5)
        
        # BPCS options
        self.bpcs_frame = ttk.Frame(options_frame)
        self.bpcs_frame.grid(column=0, row=4, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.bpcs_frame, text="Threshold [0.1, 0.5]:").pack(side=tk.LEFT, padx=5)
        threshold_entry = ttk.Entry(self.bpcs_frame, textvariable=self.threshold, width=10)
        threshold_entry.pack(side=tk.LEFT, padx=5)
        
        # Initially hide BPCS options
        self.bpcs_frame.grid_remove()
        
        # Key requirement note for non-sequential embedding
        self.nonseq_key_note = ttk.Label(options_frame, text="Note: Non-sequential embedding requires a key")
        self.nonseq_key_note.grid(column=0, row=5, columnspan=2, sticky=tk.W, padx=5, pady=5)
        self.nonseq_key_note.grid_remove()  # Initially hidden
        
        # Buttons
        ttk.Button(button_frame, text="Embed Message", command=self.embed_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Show Images", command=self.show_images).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_fields).pack(side=tk.LEFT, padx=5)

    def setup_extract_tab(self, parent):
        # Create frames
        input_frame = ttk.LabelFrame(parent, text="Input/Output", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        options_frame = ttk.LabelFrame(parent, text="Options", padding=10)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        button_frame = ttk.Frame(parent, padding=10)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        results_frame = ttk.LabelFrame(parent, text="Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Input fields
        ttk.Label(input_frame, text="Stego Image:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.stego_path, width=50).grid(column=1, row=0, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_stego_input).grid(column=2, row=0, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Output File:").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.extraction_path, width=50).grid(column=1, row=1, padx=5, pady=5)
        ttk.Button(input_frame, text="Browse...", command=self.browse_extraction).grid(column=2, row=1, padx=5, pady=5)
        
        # Options (similar to embed tab)
        ttk.Label(options_frame, text="Method:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo = ttk.Combobox(options_frame, textvariable=self.method, state="readonly")
        method_combo['values'] = ('lsb', 'bpcs')
        method_combo.grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo.bind('<<ComboboxSelected>>', self.update_extract_options_visibility)
        
        # Encryption options
        ttk.Label(options_frame, text="Encrypt message?").grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        extract_encrypt_frame = ttk.Frame(options_frame)
        extract_encrypt_frame.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        self.extract_encrypt_yes = ttk.Radiobutton(extract_encrypt_frame, text="Yes", variable=self.encryption_type, value="vigenere", command=self.update_key_visibility)
        self.extract_encrypt_no = ttk.Radiobutton(extract_encrypt_frame, text="No", variable=self.encryption_type, value="none", command=self.update_key_visibility)
        self.extract_encrypt_yes.pack(side=tk.LEFT, padx=5)
        self.extract_encrypt_no.pack(side=tk.LEFT, padx=5)
        
        # Key input
        extract_key_label = ttk.Label(options_frame, text="Enter secret key (max 25 chars):")
        extract_key_label.grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        extract_key_entry = ttk.Entry(options_frame, textvariable=self.stego_key, width=30, show="*")
        extract_key_entry.grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide key fields
        extract_key_label.grid_remove()
        extract_key_entry.grid_remove()
        
        # Method-specific options
        # LSB options
        self.extract_lsb_frame = ttk.Frame(options_frame)
        self.extract_lsb_frame.grid(column=0, row=3, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.extract_lsb_frame, text="Use sequential embedding?").pack(side=tk.LEFT, padx=5)
        extract_seq_yes = ttk.Radiobutton(self.extract_lsb_frame, text="Yes", variable=self.is_sequential, value=True, command=self.update_sequential_state)
        extract_seq_no = ttk.Radiobutton(self.extract_lsb_frame, text="No", variable=self.is_sequential, value=False, command=self.update_sequential_state)
        extract_seq_yes.pack(side=tk.LEFT, padx=5)
        extract_seq_no.pack(side=tk.LEFT, padx=5)
        
        # BPCS options
        self.extract_bpcs_frame = ttk.Frame(options_frame)
        self.extract_bpcs_frame.grid(column=0, row=4, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(self.extract_bpcs_frame, text="Threshold [0.1, 0.5]:").pack(side=tk.LEFT, padx=5)
        extract_threshold_entry = ttk.Entry(self.extract_bpcs_frame, textvariable=self.threshold, width=10)
        extract_threshold_entry.pack(side=tk.LEFT, padx=5)
        
        # Initially hide BPCS options
        self.extract_bpcs_frame.grid_remove()
        
        # Key requirement note for non-sequential embedding
        self.extract_nonseq_key_note = ttk.Label(options_frame, text="Note: Non-sequential embedding requires a key")
        self.extract_nonseq_key_note.grid(column=0, row=5, columnspan=2, sticky=tk.W, padx=5, pady=5)
        self.extract_nonseq_key_note.grid_remove()  # Initially hidden
        
        # Results area
        self.results_text = tk.Text(results_frame, height=10, width=60)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Buttons
        ttk.Button(button_frame, text="Extract Message", command=self.extract_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Verify Message", command=self.verify_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_results).pack(side=tk.LEFT, padx=5)

    def update_options_visibility(self, event=None):
        # Show/hide method-specific options for embedding tab
        if self.method.get() == 'bpcs':
            self.lsb_frame.grid_remove()
            self.bpcs_frame.grid()
            self.nonseq_key_note.grid_remove()
        else:
            self.bpcs_frame.grid_remove()
            self.lsb_frame.grid()
            # Check if we need to show the note about non-sequential requiring key
            self.update_sequential_state()

    def update_extract_options_visibility(self, event=None):
        # Show/hide method-specific options for extraction tab
        if self.method.get() == 'bpcs':
            self.extract_lsb_frame.grid_remove()
            self.extract_bpcs_frame.grid()
            self.extract_nonseq_key_note.grid_remove()
        else:
            self.extract_bpcs_frame.grid_remove()
            self.extract_lsb_frame.grid()
            # Check if we need to show the note about non-sequential requiring key
            self.update_sequential_state()

    def update_key_visibility(self, event=None):
        # Show/hide key field based on encryption selection
        if self.encryption_type.get() == 'vigenere':
            self.key_label.grid()
            self.key_entry.grid()
        else:
            # Only hide key if sequential is True, otherwise we need key for non-sequential
            if self.is_sequential.get() or self.method.get() == 'bpcs':
                self.key_label.grid_remove()
                self.key_entry.grid_remove()

    def update_sequential_state(self, event=None):
        # This method handles updates when sequential embedding checkbox changes
        if not self.is_sequential.get() and self.method.get() == 'lsb':
            # Non-sequential selected - show key field and note
            self.key_label.grid()
            self.key_entry.grid()
            self.nonseq_key_note.grid()
            self.extract_nonseq_key_note.grid()
        else:
            # Sequential selected - check if we should hide key field
            if self.encryption_type.get() != 'vigenere':
                self.key_label.grid_remove()
                self.key_entry.grid_remove()
            self.nonseq_key_note.grid_remove()
            self.extract_nonseq_key_note.grid_remove()

    def browse_cover(self):
        filename = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            # Just store the filename, not the full path with "media/"
            self.cover_path.set(os.path.basename(filename))

    def browse_message(self):
        filename = filedialog.askopenfilename(
            title="Select Message File",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            # Just store the filename, not the full path with "media/"
            self.message_path.set(os.path.basename(filename))

    def browse_stego_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Stego Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if filename:
            # Just store the filename, not the full path with "stego/"
            self.stego_path.set(os.path.basename(filename))

    def browse_stego_input(self):
        filename = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            # Just store the filename, not the full path with "stego/"
            self.stego_path.set(os.path.basename(filename))

    def browse_extraction(self):
        filename = filedialog.asksaveasfilename(
            title="Save Extracted File",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            # Just store the filename, not the full path with "extraction/"
            self.extraction_path.set(os.path.basename(filename))

    def embed_message(self):
        try:
            # Get parameters
            cover_path = "media/" + self.cover_path.get()
            message_path = "media/" + self.message_path.get()
            stego_path = "stego/" + self.stego_path.get()
            stego_key = self.stego_key.get() if self.stego_key.get() else None
            encryption_type = self.encryption_type.get() if self.encryption_type.get() == 'vigenere' else None
            is_sequential = self.is_sequential.get()
            method = self.method.get()
            threshold = self.threshold.get()
            
            # Validate inputs
            if not os.path.exists(cover_path):
                messagebox.showerror("Error", f"Cover image file does not exist: {cover_path}")
                return
                
            if not os.path.exists(message_path):
                messagebox.showerror("Error", f"Message file does not exist: {message_path}")
                return
                
            # Validate threshold for BPCS
            if method == 'bpcs':
                if threshold < 0.1 or threshold > 0.5:
                    messagebox.showwarning("Warning", "BPCS threshold should be between 0.1 and 0.5. Using default 0.3.")
                    threshold = 0.3
            
            # Check if we need a key but none is provided
            if (encryption_type == 'vigenere' or (method == 'lsb' and not is_sequential)) and not stego_key:
                messagebox.showerror("Error", "A key is required for Vigenere encryption or non-sequential LSB.")
                return
            
            # Check if key is too long
            if stego_key and len(stego_key) > 25:
                messagebox.showerror("Error", "Key must be 25 characters or less.")
                return
            
            self.status_var.set("Embedding message...")
            self.root.update()
            
            # Select embedding method
            if method == 'lsb':
                encode_lsb(cover_path, message_path, stego_path, stego_key, encryption_type, is_sequential)
            else:  # BPCS
                encode_bpcs(cover_path, message_path, stego_path, threshold=threshold, stego_key=stego_key, encryption_type=encryption_type)
            
            # Calculate PSNR
            psnr = calculate_psnr(cover_path, stego_path)
            
            self.status_var.set(f"Message embedded successfully! PSNR: {psnr:.2f} dB")
            messagebox.showinfo("Success", f"Message embedded successfully!\nPSNR: {psnr:.2f} dB")
            
            # Show images
            self.show_images(cover_path, stego_path)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error during embedding")

    def extract_message(self):
        try:
            # Get parameters
            stego_path = "stego/" + self.stego_path.get()
            extraction_path = "extraction/" + self.extraction_path.get()
            stego_key = self.stego_key.get() if self.stego_key.get() else None
            encryption_type = self.encryption_type.get() if self.encryption_type.get() == 'vigenere' else None
            is_sequential = self.is_sequential.get()
            method = self.method.get()
            threshold = self.threshold.get()
            
            # Validate inputs
            if not os.path.exists(stego_path):
                messagebox.showerror("Error", f"Stego image file does not exist: {stego_path}")
                return
                
            # Validate threshold for BPCS
            if method == 'bpcs':
                if threshold < 0.1 or threshold > 0.5:
                    messagebox.showwarning("Warning", "BPCS threshold should be between 0.1 and 0.5. Using default 0.3.")
                    threshold = 0.3
            
            # Check if we need a key but none is provided
            if (encryption_type == 'vigenere' or (method == 'lsb' and not is_sequential)) and not stego_key:
                messagebox.showerror("Error", "A key is required for Vigenere encryption or non-sequential LSB.")
                return
            
            # Check if key is too long
            if stego_key and len(stego_key) > 25:
                messagebox.showerror("Error", "Key must be 25 characters or less.")
                return
            
            self.status_var.set("Extracting message...")
            self.root.update()
            
            # Select extraction method
            if method == 'lsb':
                decode_lsb(stego_path, extraction_path, stego_key, encryption_type, is_sequential)
            else:  # BPCS
                decode_bpcs(stego_path, extraction_path, threshold=threshold, stego_key=stego_key, encryption_type=encryption_type)
            
            self.status_var.set("Message extracted successfully!")
            self.results_text.insert(tk.END, f"Message extracted to {extraction_path}\n")
            messagebox.showinfo("Success", f"Message extracted to {extraction_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error during extraction")

    def verify_message(self):
        try:
            # Get paths
            original_file = "media/" + self.message_path.get()
            extracted_file = "extraction/" + self.extraction_path.get()
            
            # Validate inputs
            if not os.path.exists(original_file):
                messagebox.showerror("Error", f"Original message file does not exist: {original_file}")
                return
                
            if not os.path.exists(extracted_file):
                messagebox.showerror("Error", f"Extracted file does not exist: {extracted_file}")
                return
            
            self.status_var.set("Verifying message...")
            self.root.update()
            
            # Simple binary comparison
            with open(original_file, 'rb') as f1, open(extracted_file, 'rb') as f2:
                original_data = f1.read()
                extracted_data = f2.read()
                result = original_data == extracted_data
            
            if result:
                self.results_text.insert(tk.END, "Verification result: Files are identical!\n")
                messagebox.showinfo("Verification", "Files are identical!")
            else:
                # Calculate how many bytes differ
                min_len = min(len(original_data), len(extracted_data))
                different_bytes = sum(1 for i in range(min_len) if original_data[i] != extracted_data[i])
                size_diff = abs(len(original_data) - len(extracted_data))
                
                self.results_text.insert(tk.END, f"Verification result: Files differ!\n")
                self.results_text.insert(tk.END, f"Different bytes: {different_bytes}, Size difference: {size_diff} bytes\n")
                messagebox.showwarning("Verification", f"Files differ!\nDifferent bytes: {different_bytes}, Size difference: {size_diff} bytes")
            
            self.status_var.set("Verification complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during verification: {str(e)}")
            self.status_var.set("Error during verification")

    def show_images(self, cover_path=None, stego_path=None):
        # Use provided paths or the ones from fields
        if not cover_path:
            cover_path = "media/" + self.cover_path.get()
        if not stego_path:
            stego_path = "stego/" + self.stego_path.get()
        
        # Check if images exist
        if not os.path.exists(cover_path):
            messagebox.showerror("Error", f"Cover image file does not exist: {cover_path}")
            return
            
        if not os.path.exists(stego_path):
            messagebox.showerror("Error", f"Stego image file does not exist: {stego_path}")
            return
        
        # Close existing windows if open
        if self.original_window is not None and self.original_window.winfo_exists():
            self.original_window.destroy()
            
        if self.stego_window is not None and self.stego_window.winfo_exists():
            self.stego_window.destroy()
        
        # Create new windows for images
        self.original_window = tk.Toplevel(self.root)
        self.original_window.title("Original Cover Image")
        
        self.stego_window = tk.Toplevel(self.root)
        self.stego_window.title("Stego Image")
        
        # Load images
        original_img = Image.open(cover_path)
        stego_img = Image.open(stego_path)
        
        # Calculate appropriate size for display (max 800x600)
        max_width, max_height = 800, 600
        
        # Resize original image if needed
        orig_width, orig_height = original_img.size
        if orig_width > max_width or orig_height > max_height:
            scale = min(max_width/orig_width, max_height/orig_height)
            new_width = int(orig_width * scale)
            new_height = int(orig_height * scale)
            original_img = original_img.resize((new_width, new_height), Image.LANCZOS)
        
        # Resize stego image if needed
        stego_width, stego_height = stego_img.size
        if stego_width > max_width or stego_height > max_height:
            scale = min(max_width/stego_width, max_height/stego_height)
            new_width = int(stego_width * scale)
            new_height = int(stego_height * scale)
            stego_img = stego_img.resize((new_width, new_height), Image.LANCZOS)
        
        # Convert to PhotoImage
        self.original_photo = ImageTk.PhotoImage(original_img)
        self.stego_photo = ImageTk.PhotoImage(stego_img)
        
        # Create labels to display images
        original_label = ttk.Label(self.original_window, image=self.original_photo)
        original_label.pack(padx=10, pady=10)
        
        stego_label = ttk.Label(self.stego_window, image=self.stego_photo)
        stego_label.pack(padx=10, pady=10)
        
        # Add info to image windows
        ttk.Label(self.original_window, text=f"File: {os.path.basename(cover_path)}").pack(pady=5)
        ttk.Label(self.stego_window, text=f"File: {os.path.basename(stego_path)}").pack(pady=5)
        
        # Add PSNR info to stego window
        try:
            psnr = calculate_psnr(cover_path, stego_path)
            psnr_label = ttk.Label(self.stego_window, text=f"PSNR: {psnr:.2f} dB")
            psnr_label.pack(pady=5)
        except:
            pass

    def clear_fields(self):
        self.cover_path.set("")
        self.message_path.set("")
        self.stego_path.set("stego_output.png")
        self.extraction_path.set("extracted_file")
        self.stego_key.set("")
        self.encryption_type.set("none")
        self.is_sequential.set(True)
        self.method.set("lsb")
        self.threshold.set(0.3)
        self.status_var.set("Ready")

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
