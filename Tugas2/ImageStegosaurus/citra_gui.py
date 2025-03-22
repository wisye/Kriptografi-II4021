import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np
from stegano_api import encode_lsb, decode_lsb, verify_lsb, calculate_psnr, encode_bpcs, decode_bpcs

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Tool")
        self.root.geometry("800x620")
        self.root.configure(bg="#f0f0f0")
        
        # Variables
        self.cover_path = tk.StringVar()
        self.message_path = tk.StringVar()
        self.stego_path = tk.StringVar(value="stego/stego_output.png")
        self.extraction_path = tk.StringVar(value="extraction/extracted_file")
        self.stego_key = tk.StringVar()
        self.encryption_type = tk.StringVar(value="none")
        self.is_sequential = tk.BooleanVar(value=True)
        self.method = tk.StringVar(value="lsb")
        self.threshold = tk.DoubleVar(value=0.3)
        self.use_media_prefix = tk.BooleanVar(value=False)
        
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
        
        # Media prefix option
        ttk.Checkbutton(input_frame, text="Use 'media/' prefix for input files", variable=self.use_media_prefix).grid(column=0, row=3, columnspan=3, sticky=tk.W, padx=5, pady=5)
        
        # Options
        ttk.Label(options_frame, text="Method:").grid(column=0, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo = ttk.Combobox(options_frame, textvariable=self.method, state="readonly")
        method_combo['values'] = ('lsb', 'bpcs')
        method_combo.grid(column=1, row=0, sticky=tk.W, padx=5, pady=5)
        method_combo.bind('<<ComboboxSelected>>', self.update_options_visibility)
        
        # BPCS threshold (initially hidden)
        self.threshold_label = ttk.Label(options_frame, text="BPCS Threshold [0.1, 0.5]:")
        self.threshold_label.grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        self.threshold_entry = ttk.Entry(options_frame, textvariable=self.threshold, width=10)
        self.threshold_entry.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide BPCS-specific options
        self.threshold_label.grid_remove()
        self.threshold_entry.grid_remove()
        
        ttk.Label(options_frame, text="Encryption:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        encryption_combo = ttk.Combobox(options_frame, textvariable=self.encryption_type, state="readonly")
        encryption_combo['values'] = ('none', 'vigenere')
        encryption_combo.grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        encryption_combo.bind('<<ComboboxSelected>>', self.update_key_visibility)
        
        self.key_label = ttk.Label(options_frame, text="Stego Key:")
        self.key_label.grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)
        self.key_entry = ttk.Entry(options_frame, textvariable=self.stego_key, width=30, show="*")
        self.key_entry.grid(column=1, row=3, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide key fields
        self.key_label.grid_remove()
        self.key_entry.grid_remove()
        
        # LSB Specific options
        self.sequential_check = ttk.Checkbutton(options_frame, text="Use Sequential Embedding", variable=self.is_sequential, command=self.update_sequential_state)
        self.sequential_check.grid(column=0, row=4, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
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
        method_combo.bind('<<ComboboxSelected>>', self.update_options_visibility)
        
        # BPCS threshold
        extract_threshold_label = ttk.Label(options_frame, text="BPCS Threshold [0.1, 0.5]:")
        extract_threshold_label.grid(column=0, row=1, sticky=tk.W, padx=5, pady=5)
        extract_threshold_entry = ttk.Entry(options_frame, textvariable=self.threshold, width=10)
        extract_threshold_entry.grid(column=1, row=1, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide BPCS-specific options
        extract_threshold_label.grid_remove()
        extract_threshold_entry.grid_remove()
        
        # Match options with the embed tab
        ttk.Label(options_frame, text="Encryption:").grid(column=0, row=2, sticky=tk.W, padx=5, pady=5)
        extraction_encryption_combo = ttk.Combobox(options_frame, textvariable=self.encryption_type, state="readonly")
        extraction_encryption_combo['values'] = ('none', 'vigenere')
        extraction_encryption_combo.grid(column=1, row=2, sticky=tk.W, padx=5, pady=5)
        extraction_encryption_combo.bind('<<ComboboxSelected>>', self.update_key_visibility)
        
        extract_key_label = ttk.Label(options_frame, text="Stego Key:")
        extract_key_label.grid(column=0, row=3, sticky=tk.W, padx=5, pady=5)
        extract_key_entry = ttk.Entry(options_frame, textvariable=self.stego_key, width=30, show="*")
        extract_key_entry.grid(column=1, row=3, sticky=tk.W, padx=5, pady=5)
        
        # Initially hide key fields
        extract_key_label.grid_remove()
        extract_key_entry.grid_remove()
        
        # LSB Specific options
        extract_sequential_check = ttk.Checkbutton(options_frame, text="Use Sequential Embedding", variable=self.is_sequential, command=self.update_sequential_state)
        extract_sequential_check.grid(column=0, row=4, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
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
        # Show/hide method-specific options
        if self.method.get() == 'bpcs':
            self.threshold_label.grid()
            self.threshold_entry.grid()
            self.sequential_check.grid_remove()
            self.nonseq_key_note.grid_remove()
            self.extract_nonseq_key_note.grid_remove()
        else:
            self.threshold_label.grid_remove()
            self.threshold_entry.grid_remove()
            self.sequential_check.grid()
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
            self.cover_path.set(filename)

    def browse_message(self):
        filename = filedialog.askopenfilename(
            title="Select Message File",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.message_path.set(filename)

    def browse_stego_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Stego Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if filename:
            self.stego_path.set(filename)

    def browse_stego_input(self):
        filename = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if filename:
            self.stego_path.set(filename)

    def browse_extraction(self):
        filename = filedialog.asksaveasfilename(
            title="Save Extracted File",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.extraction_path.set(filename)

    def embed_message(self):
        try:
            # Prepare paths with media prefix if needed
            cover_path = self.cover_path.get()
            message_path = self.message_path.get()
            
            if self.use_media_prefix.get():
                if not cover_path.startswith("media/"):
                    cover_path = "media/" + cover_path
                if not message_path.startswith("media/"):
                    message_path = "media/" + message_path
            
            # Validate inputs
            if not os.path.exists(cover_path):
                messagebox.showerror("Error", f"Cover image file does not exist: {cover_path}")
                return
                
            if not os.path.exists(message_path):
                messagebox.showerror("Error", f"Message file does not exist: {message_path}")
                return
            
            # Get parameters
            stego_path = self.stego_path.get()
            stego_key = self.stego_key.get()
            encryption_type = self.encryption_type.get() if self.encryption_type.get() != 'none' else None
            is_sequential = self.is_sequential.get()
            method = self.method.get()
            threshold = self.threshold.get()
            
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
            
            # Only pass stego_key to function if we need it
            if encryption_type != 'vigenere' and (method != 'lsb' or is_sequential):
                stego_key = None
            
            self.status_var.set("Embedding message...")
            self.root.update()
            
            # Select embedding method
            if method == 'lsb':
                encode_lsb(cover_path, message_path, stego_path, stego_key, encryption_type, is_sequential)
            else:  # BPCS
                encode_bpcs(cover_path, message_path, stego_path, threshold, stego_key, encryption_type)
            
            # Calculate PSNR
            psnr = calculate_psnr(cover_path, stego_path)
            
            self.status_var.set(f"Message embedded successfully! PSNR: {psnr:.2f} dB")
            messagebox.showinfo("Success", f"Message embedded successfully!\nPSNR: {psnr:.2f} dB")
            
            # Show images
            self.show_images(cover_path)
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error during embedding")

    def extract_message(self):
        try:
            # Validate inputs
            stego_path = self.stego_path.get()
            if not os.path.exists(stego_path):
                messagebox.showerror("Error", "Stego image file does not exist!")
                return
            
            # Get parameters
            extraction_path = self.extraction_path.get()
            stego_key = self.stego_key.get()
            encryption_type = self.encryption_type.get() if self.encryption_type.get() != 'none' else None
            is_sequential = self.is_sequential.get()
            method = self.method.get()
            threshold = self.threshold.get()
            
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
            
            # Only pass stego_key to function if we need it
            if encryption_type != 'vigenere' and (method != 'lsb' or is_sequential):
                stego_key = None
            
            self.status_var.set("Extracting message...")
            self.root.update()
            
            # Select extraction method
            if method == 'lsb':
                decode_lsb(stego_path, extraction_path, stego_key, encryption_type, is_sequential)
            else:  # BPCS
                decode_bpcs(stego_path, extraction_path, threshold, stego_key, encryption_type)
            
            self.status_var.set("Message extracted successfully!")
            self.results_text.insert(tk.END, f"Message extracted to {extraction_path}\n")
            messagebox.showinfo("Success", f"Message extracted to {extraction_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error during extraction")

    def verify_message(self):
        try:
            # Validate inputs
            original_file = self.message_path.get()
            extracted_file = self.extraction_path.get()
            
            if self.use_media_prefix.get() and not original_file.startswith("media/"):
                original_file = "media/" + original_file
            
            if not os.path.exists(original_file):
                messagebox.showerror("Error", "Original message file does not exist!")
                return
                
            if not os.path.exists(extracted_file):
                messagebox.showerror("Error", "Extracted file does not exist!")
                return
            
            self.status_var.set("Verifying message...")
            self.root.update()
            
            # Use the appropriate verify function
            if self.method.get() == 'lsb':
                result = verify_lsb(original_file, extracted_file)
            else:
                # Using generic verification for BPCS
                with open(original_file, 'rb') as f1, open(extracted_file, 'rb') as f2:
                    original_data = f1.read()
                    extracted_data = f2.read()
                result = original_data == extracted_data
            
            if result:
                self.results_text.insert(tk.END, "Verification result: Files are identical!\n")
                messagebox.showinfo("Verification", "Files are identical!")
            else:
                self.results_text.insert(tk.END, "Verification result: Files differ!\n")
                messagebox.showwarning("Verification", "Files differ!")
            
            self.status_var.set("Verification complete")
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during verification: {str(e)}")
            self.status_var.set("Error during verification")

    def show_images(self, cover_path=None):
        # Use provided cover path or the one from the field
        if not cover_path:
            cover_path = self.cover_path.get()
            if self.use_media_prefix.get() and not cover_path.startswith("media/"):
                cover_path = "media/" + cover_path
        
        # Check if cover and stego images exist
        if not os.path.exists(cover_path):
            messagebox.showerror("Error", f"Cover image file does not exist: {cover_path}")
            return
            
        if not os.path.exists(self.stego_path.get()):
            messagebox.showerror("Error", "Stego image file does not exist!")
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
        stego_img = Image.open(self.stego_path.get())
        
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
        
        # Add PSNR info to stego window
        try:
            psnr = calculate_psnr(cover_path, self.stego_path.get())
            psnr_label = ttk.Label(self.stego_window, text=f"PSNR: {psnr:.2f} dB")
            psnr_label.pack(pady=5)
        except:
            pass

    def clear_fields(self):
        self.cover_path.set("")
        self.message_path.set("")
        self.stego_path.set("stego/stego_output.png")
        self.extraction_path.set("extraction/extracted_file")
        self.stego_key.set("")
        self.encryption_type.set("none")
        self.is_sequential.set(True)
        self.method.set("lsb")
        self.threshold.set(0.3)
        self.use_media_prefix.set(False)
        self.status_var.set("Ready")

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Ready")

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()