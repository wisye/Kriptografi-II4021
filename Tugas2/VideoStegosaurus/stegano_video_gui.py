import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, 
                            QComboBox, QCheckBox, QProgressBar, QMessageBox, QGroupBox,
                            QRadioButton, QButtonGroup, QTextEdit, QSplitter)
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtCore import Qt, QThread, pyqtSignal

# Import functions from your original file
from stegano_video import (embed_message_in_video, extract_message_from_video, 
                          calculate_video_psnr)

class WorkerThread(QThread):
    """Worker thread for running time-consuming operations."""
    update_progress = pyqtSignal(int)
    update_status = pyqtSignal(str)
    operation_complete = pyqtSignal(str)
    
    def __init__(self, operation, *args, **kwargs):
        super().__init__()
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        try:
            if self.operation == "embed":
                self.update_status.emit("Extracting frames...")
                self.update_progress.emit(10)
                embed_message_in_video(*self.args, **self.kwargs)
                self.update_progress.emit(100)
                self.operation_complete.emit("Message embedded successfully!")
                
            elif self.operation == "extract":
                self.update_status.emit("Extracting message...")
                self.update_progress.emit(50)
                extract_message_from_video(*self.args, **self.kwargs)
                self.update_progress.emit(100)
                self.operation_complete.emit("Message extracted successfully!")
                
            elif self.operation == "psnr":
                self.update_status.emit("Calculating PSNR...")
                self.update_progress.emit(30)
                psnr = calculate_video_psnr(*self.args, **self.kwargs)
                self.update_progress.emit(100)
                self.operation_complete.emit(f"Average PSNR: {psnr:.2f} dB")
        except Exception as e:
            self.operation_complete.emit(f"Error: {str(e)}")


class VideoSteganographyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("Video Steganography")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QTabWidget {
                background-color: white;
                border-radius: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                border: 1px solid #ccc;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 1px solid white;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3b78de;
            }
            QPushButton:pressed {
                background-color: #3069c7;
            }
            QGroupBox {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            QLineEdit {
                border: 1px solid #ddd;
                border-radius: 3px;
                padding: 5px;
            }
            QComboBox {
                border: 1px solid #ddd;
                border-radius: 3px;
                padding: 5px;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4a86e8;
            }
        """)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Create tabs
        self.embed_tab = QWidget()
        self.extract_tab = QWidget()
        self.psnr_tab = QWidget()
        
        # Add tabs to widget
        self.tabs.addTab(self.embed_tab, "Embed Message")
        self.tabs.addTab(self.extract_tab, "Extract Message")
        self.tabs.addTab(self.psnr_tab, "Calculate PSNR")
        
        # Set up each tab
        self.setup_embed_tab()
        self.setup_extract_tab()
        self.setup_psnr_tab()
        
    def setup_embed_tab(self):
        layout = QVBoxLayout()
        
        # Input video section
        input_group = QGroupBox("Input Video")
        input_layout = QHBoxLayout()
        
        self.input_video_path = QLineEdit()
        self.input_video_path.setPlaceholderText("Select input video file...")
        self.input_video_btn = QPushButton("Browse")
        self.input_video_btn.clicked.connect(lambda: self.browse_file(self.input_video_path, "Video Files (*.mp4 *.avi *.mov *.mkv)"))
        
        input_layout.addWidget(self.input_video_path)
        input_layout.addWidget(self.input_video_btn)
        input_group.setLayout(input_layout)
        
        # Message file section
        message_group = QGroupBox("Message File")
        message_layout = QHBoxLayout()
        
        self.message_file_path = QLineEdit()
        self.message_file_path.setPlaceholderText("Select message file to hide...")
        self.message_file_btn = QPushButton("Browse")
        self.message_file_btn.clicked.connect(lambda: self.browse_file(self.message_file_path, "All Files (*)"))
        
        message_layout.addWidget(self.message_file_path)
        message_layout.addWidget(self.message_file_btn)
        message_group.setLayout(message_layout)
        
        # Output video section
        output_group = QGroupBox("Output Video")
        output_layout = QHBoxLayout()
        
        self.output_video_path = QLineEdit()
        self.output_video_path.setPlaceholderText("Select where to save stego video...")
        self.output_video_btn = QPushButton("Browse")
        self.output_video_btn.clicked.connect(lambda: self.save_file(self.output_video_path, "AVI Files (*.avi)"))
        
        output_layout.addWidget(self.output_video_path)
        output_layout.addWidget(self.output_video_btn)
        output_group.setLayout(output_layout)
        
        # Steganography options
        options_group = QGroupBox("Steganography Options")
        options_layout = QVBoxLayout()
        
        # Stego key
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Stego Key:"))
        self.stego_key_input = QLineEdit()
        self.stego_key_input.setPlaceholderText("Enter a key (optional)")
        key_layout.addWidget(self.stego_key_input)
        
        # Encryption 
        encrypt_layout = QHBoxLayout()
        encrypt_layout.addWidget(QLabel("Encryption:"))
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["none", "vigenere"])
        encrypt_layout.addWidget(self.encryption_combo)
        
        # Embedding method
        embedding_layout = QVBoxLayout()
        embedding_layout.addWidget(QLabel("Embedding Method:"))
        
        self.sequential_radio = QRadioButton("Sequential")
        self.sequential_radio.setChecked(True)
        self.random_radio = QRadioButton("Random")
        
        radio_layout = QHBoxLayout()
        radio_layout.addWidget(self.sequential_radio)
        radio_layout.addWidget(self.random_radio)
        embedding_layout.addLayout(radio_layout)
        
        # Add all option layouts
        options_layout.addLayout(key_layout)
        options_layout.addLayout(encrypt_layout)
        options_layout.addLayout(embedding_layout)
        options_group.setLayout(options_layout)
        
        # Progress and status
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.embed_progress = QProgressBar()
        self.embed_status = QLabel("Ready")
        
        progress_layout.addWidget(self.embed_progress)
        progress_layout.addWidget(self.embed_status)
        progress_group.setLayout(progress_layout)
        
        # Embed button
        self.embed_btn = QPushButton("Embed Message")
        self.embed_btn.clicked.connect(self.start_embedding)
        
        # Add all components to main layout
        layout.addWidget(input_group)
        layout.addWidget(message_group)
        layout.addWidget(output_group)
        layout.addWidget(options_group)
        layout.addWidget(progress_group)
        layout.addWidget(self.embed_btn)
        
        self.embed_tab.setLayout(layout)
        
    def setup_extract_tab(self):
        layout = QVBoxLayout()
        
        # Stego video section
        stego_group = QGroupBox("Stego Video")
        stego_layout = QHBoxLayout()
        
        self.stego_video_path = QLineEdit()
        self.stego_video_path.setPlaceholderText("Select stego video file...")
        self.stego_video_btn = QPushButton("Browse")
        self.stego_video_btn.clicked.connect(lambda: self.browse_file(self.stego_video_path, "Video Files (*.mp4 *.avi *.mov *.mkv)"))
        
        stego_layout.addWidget(self.stego_video_path)
        stego_layout.addWidget(self.stego_video_btn)
        stego_group.setLayout(stego_layout)
        
        # Output file section
        extract_group = QGroupBox("Output File")
        extract_layout = QHBoxLayout()
        
        self.extract_file_path = QLineEdit()
        self.extract_file_path.setPlaceholderText("Select where to save extracted message...")
        self.extract_file_btn = QPushButton("Browse")
        self.extract_file_btn.clicked.connect(lambda: self.save_file(self.extract_file_path, "All Files (*)"))
        
        extract_layout.addWidget(self.extract_file_path)
        extract_layout.addWidget(self.extract_file_btn)
        extract_group.setLayout(extract_layout)
        
        # Extraction options
        options_group = QGroupBox("Extraction Options")
        options_layout = QVBoxLayout()
        
        # Stego key
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Stego Key:"))
        self.extract_key_input = QLineEdit()
        self.extract_key_input.setPlaceholderText("Enter the same key used for embedding")
        key_layout.addWidget(self.extract_key_input)
        
        # Encryption 
        encrypt_layout = QHBoxLayout()
        encrypt_layout.addWidget(QLabel("Encryption:"))
        self.extract_encryption_combo = QComboBox()
        self.extract_encryption_combo.addItems(["none", "vigenere"])
        encrypt_layout.addWidget(self.extract_encryption_combo)
        
        # Embedding method
        embedding_layout = QVBoxLayout()
        embedding_layout.addWidget(QLabel("Original Embedding Method:"))
        
        self.extract_sequential_radio = QRadioButton("Sequential")
        self.extract_sequential_radio.setChecked(True)
        self.extract_random_radio = QRadioButton("Random")
        
        radio_layout = QHBoxLayout()
        radio_layout.addWidget(self.extract_sequential_radio)
        radio_layout.addWidget(self.extract_random_radio)
        embedding_layout.addLayout(radio_layout)
        
        # Add all option layouts
        options_layout.addLayout(key_layout)
        options_layout.addLayout(encrypt_layout)
        options_layout.addLayout(embedding_layout)
        options_group.setLayout(options_layout)
        
        # Progress and status
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.extract_progress = QProgressBar()
        self.extract_status = QLabel("Ready")
        
        progress_layout.addWidget(self.extract_progress)
        progress_layout.addWidget(self.extract_status)
        progress_group.setLayout(progress_layout)
        
        # Extract button
        self.extract_btn = QPushButton("Extract Message")
        self.extract_btn.clicked.connect(self.start_extracting)
        
        # Add all components to main layout
        layout.addWidget(stego_group)
        layout.addWidget(extract_group)
        layout.addWidget(options_group)
        layout.addWidget(progress_group)
        layout.addWidget(self.extract_btn)
        
        self.extract_tab.setLayout(layout)
    
    def setup_psnr_tab(self):
        layout = QVBoxLayout()
        
        # Original video section
        original_group = QGroupBox("Original Video")
        original_layout = QHBoxLayout()
        
        self.original_video_path = QLineEdit()
        self.original_video_path.setPlaceholderText("Select original video file...")
        self.original_video_btn = QPushButton("Browse")
        self.original_video_btn.clicked.connect(lambda: self.browse_file(self.original_video_path, "Video Files (*.mp4 *.avi *.mov *.mkv)"))
        
        original_layout.addWidget(self.original_video_path)
        original_layout.addWidget(self.original_video_btn)
        original_group.setLayout(original_layout)
        
        # Stego video section
        stego_group = QGroupBox("Stego Video")
        stego_layout = QHBoxLayout()
        
        self.psnr_stego_video_path = QLineEdit()
        self.psnr_stego_video_path.setPlaceholderText("Select stego video file...")
        self.psnr_stego_video_btn = QPushButton("Browse")
        self.psnr_stego_video_btn.clicked.connect(lambda: self.browse_file(self.psnr_stego_video_path, "Video Files (*.mp4 *.avi *.mov *.mkv)"))
        
        stego_layout.addWidget(self.psnr_stego_video_path)
        stego_layout.addWidget(self.psnr_stego_video_btn)
        stego_group.setLayout(stego_layout)
        
        # Results section
        results_group = QGroupBox("PSNR Results")
        results_layout = QVBoxLayout()
        
        self.psnr_progress = QProgressBar()
        self.psnr_result = QLabel("PSNR will be displayed here")
        self.psnr_result.setAlignment(Qt.AlignCenter)
        self.psnr_result.setFont(QFont("Arial", 12, QFont.Bold))
        
        results_layout.addWidget(self.psnr_progress)
        results_layout.addWidget(self.psnr_result)
        results_group.setLayout(results_layout)
        
        # Calculate button
        self.calculate_btn = QPushButton("Calculate PSNR")
        self.calculate_btn.clicked.connect(self.start_psnr_calculation)
        
        # Add all components to main layout
        layout.addWidget(original_group)
        layout.addWidget(stego_group)
        layout.addWidget(results_group)
        layout.addWidget(self.calculate_btn)
        
        self.psnr_tab.setLayout(layout)
    
    def browse_file(self, line_edit, file_filter):
        filename, _ = QFileDialog.getOpenFileName(self, "Select File", "", file_filter)
        if filename:
            line_edit.setText(filename)
    
    def save_file(self, line_edit, file_filter):
        filename, _ = QFileDialog.getSaveFileName(self, "Save File", "", file_filter)
        if filename:
            # Add .avi extension if not present for video files
            if file_filter == "AVI Files (*.avi)" and not filename.lower().endswith('.avi'):
                filename += '.avi'
            line_edit.setText(filename)
    
    def start_embedding(self):
        if not self.input_video_path.text() or not self.message_file_path.text() or not self.output_video_path.text():
            QMessageBox.warning(self, "Missing Information", "Please fill in all file paths.")
            return
        
        self.embed_btn.setEnabled(False)
        self.embed_progress.setValue(0)
        self.embed_status.setText("Starting...")
        
        # Get parameters
        video_path = self.input_video_path.text()
        msg_file = self.message_file_path.text()
        output_video = self.output_video_path.text()
        stego_key = self.stego_key_input.text() if self.stego_key_input.text() else None
        encryption_type = self.encryption_combo.currentText() if self.encryption_combo.currentText() != "none" else None
        is_sequential = self.sequential_radio.isChecked()
        
        # Start worker thread
        self.thread = WorkerThread("embed", video_path, msg_file, output_video, stego_key, encryption_type, is_sequential)
        self.thread.update_progress.connect(self.embed_progress.setValue)
        self.thread.update_status.connect(self.embed_status.setText)
        self.thread.operation_complete.connect(self.embed_complete)
        self.thread.start()
    
    def embed_complete(self, message):
        self.embed_status.setText(message)
        self.embed_btn.setEnabled(True)
        QMessageBox.information(self, "Embedding Complete", message)
    
    def start_extracting(self):
        if not self.stego_video_path.text() or not self.extract_file_path.text():
            QMessageBox.warning(self, "Missing Information", "Please fill in all file paths.")
            return
        
        self.extract_btn.setEnabled(False)
        self.extract_progress.setValue(0)
        self.extract_status.setText("Starting extraction...")
        
        # Get parameters
        stego_video = self.stego_video_path.text()
        output_file = self.extract_file_path.text()
        stego_key = self.extract_key_input.text() if self.extract_key_input.text() else None
        encryption_type = self.extract_encryption_combo.currentText() if self.extract_encryption_combo.currentText() != "none" else None
        is_sequential = self.extract_sequential_radio.isChecked()
        
        # Start worker thread
        self.thread = WorkerThread("extract", stego_video, output_file, stego_key, encryption_type, is_sequential)
        self.thread.update_progress.connect(self.extract_progress.setValue)
        self.thread.update_status.connect(self.extract_status.setText)
        self.thread.operation_complete.connect(self.extract_complete)
        self.thread.start()
    
    def extract_complete(self, message):
        self.extract_status.setText(message)
        self.extract_btn.setEnabled(True)
        QMessageBox.information(self, "Extraction Complete", message)
    
    def start_psnr_calculation(self):
        if not self.original_video_path.text() or not self.psnr_stego_video_path.text():
            QMessageBox.warning(self, "Missing Information", "Please select both original and stego videos.")
            return
        
        self.calculate_btn.setEnabled(False)
        self.psnr_progress.setValue(0)
        self.psnr_result.setText("Calculating...")
        
        # Get parameters
        original_video = self.original_video_path.text()
        stego_video = self.psnr_stego_video_path.text()
        
        # Start worker thread
        self.thread = WorkerThread("psnr", original_video, stego_video)
        self.thread.update_progress.connect(self.psnr_progress.setValue)
        self.thread.operation_complete.connect(self.psnr_complete)
        self.thread.start()
    
    def psnr_complete(self, message):
        self.psnr_result.setText(message)
        self.calculate_btn.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = VideoSteganographyApp()
    ex.show()
    sys.exit(app.exec_())