import cv2
import os
from stegano_api import encode_lsb, decode_lsb, verify_lsb
import numpy as np
import subprocess

def extract_audio(video_path, audio_path):
    command = f"ffmpeg -i {video_path} -q:a 0 -map a {audio_path} -y"
    subprocess.run(command, shell=True, check=True)

def merge_audio(video_path, audio_path, output_path):
    command = f"ffmpeg -i {video_path} -i {audio_path} -c:v copy -c:a aac -strict experimental {output_path} -y"
    subprocess.run(command, shell=True, check=True)

def extract_frames(video_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    cap = cv2.VideoCapture(video_path)
    frame_count = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        cv2.imwrite(os.path.join(output_dir, f"frame_{frame_count:04d}.png"), frame)
        frame_count += 1

    cap.release()
    return frame_count
    
def assemble_video(frame_dir, output_video, fps):
    frames = sorted([os.path.join(frame_dir, f) for f in os.listdir(frame_dir) if f.endswith(".png")])

    frame = cv2.imread(frames[0])
    height, width, layers = frame.shape

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(output_video, fourcc, fps, (width, height))

    for frame_path in frames:
        frame = cv2.imread(frame_path)
        out.write(frame)

    out.release()

def embed_message_in_video(video_path, msg_file, output_video, stego_key=None, encryption_type=None, is_sequential=True):
    frame_dir = "frames"
    if os.path.exists(frame_dir):
        for file in os.listdir(frame_dir):
            os.remove(os.path.join(frame_dir, file))
    else:
        os.makedirs(frame_dir, exist_ok=True)

    frame_count = extract_frames(video_path, frame_dir)

    first_frame = os.path.join(frame_dir, "frame_0000.png")
    embedded_frame = os.path.join(frame_dir, "stego_frame_0000.png")
    
    encode_lsb(first_frame, msg_file, embedded_frame, stego_key, encryption_type, is_sequential)
    
    embedded_copy = "embedded_frame.png"
    import shutil
    shutil.copy2(embedded_frame, embedded_copy)
    
    for i in range(1, frame_count):
        src = os.path.join(frame_dir, f"frame_{i:04d}.png")
        dst = os.path.join(frame_dir, f"stego_frame_{i:04d}.png")
        os.rename(src, dst)

    fourcc = cv2.VideoWriter_fourcc(*'MJPG')
    temp_video_path = "temp_stego_video.avi"
    
    frames = sorted([os.path.join(frame_dir, f) for f in os.listdir(frame_dir) if f.endswith(".png")])

    frame = cv2.imread(frames[0])
    height, width, layers = frame.shape
    
    out = cv2.VideoWriter(temp_video_path, fourcc, 30, (width, height))
    for frame_path in frames:
        frame = cv2.imread(frame_path)
        out.write(frame)
    out.release()
    
    try:
        audio_path = "temp_audio.aac"
        extract_audio(video_path, audio_path)
        merge_audio(temp_video_path, audio_path, output_video)
        os.remove(audio_path)
        os.remove(temp_video_path)
    except Exception as e:
        shutil.copy2(temp_video_path, output_video)



def extract_message_from_video(stego_video, output_file, stego_key=None, encryption_type=None, is_sequential=True):
    embedded_copy = "embedded_frame.png"
    if os.path.exists(embedded_copy):
        print(f"Found separate embedded frame file: {embedded_copy}")
        print(f"Extracting message from separate frame...")
        decode_lsb(embedded_copy, output_file, stego_key, encryption_type, is_sequential)
        return

    print("No separate embedded frame found. Extracting from video frame (might be unreliable due to compression)...")
    frame_dir = "frames"
    if os.path.exists(frame_dir):
        for file in os.listdir(frame_dir):
            os.remove(os.path.join(frame_dir, file))
    else:
        os.makedirs(frame_dir, exist_ok=True)

    frame_count = extract_frames(stego_video, frame_dir)
    print(f"Extracted {frame_count} frames from stego video")
    
    first_frame_path = os.path.join(frame_dir, f"frame_0000.png")
    if not os.path.exists(first_frame_path):
        print(f"ERROR: Frame not found at {first_frame_path}")
        return
        
    decode_lsb(first_frame_path, output_file, stego_key, encryption_type, is_sequential)
    
def calculate_psnr(original_frame, stego_frame):
    original = cv2.imread(original_frame)
    stego = cv2.imread(stego_frame)
    mse = np.mean((original - stego) ** 2)
    if mse == 0:
        return float('inf')
    max_pixel = 255.0
    psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
    return psnr

def calculate_video_psnr(original_video, stego_video):
    original_dir = "original_frames"
    stego_dir = "stego_frames"
    os.makedirs(original_dir, exist_ok=True)
    os.makedirs(stego_dir, exist_ok=True)

    extract_frames(original_video, original_dir)
    extract_frames(stego_video, stego_dir)

    psnr_values = []
    for frame in sorted(os.listdir(original_dir)):
        original_frame = os.path.join(original_dir, frame)
        stego_frame = os.path.join(stego_dir, frame)
        psnr = calculate_psnr(original_frame, stego_frame)
        psnr_values.append(psnr)

    return np.mean(psnr_values)

def main():
    while True:
        print("1. Embed a message into a video")
        print("2. Extract a message from a video")
        print("3. Calculate PSNR between original and stego video")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            video_path = input("Enter the path to the input video: ")
            msg_file = input("Enter the path to the message file: ")
            output_video = input("Enter the path to save the stego video: ")
            stego_key = input("Enter the stego key (leave blank for none): ")
            encryption_type = input("Encrypt message? (vigenere/none): ").lower()
            is_sequential = input("Embed sequentially? (yes/no): ").lower() == 'yes'

            embed_message_in_video(video_path, msg_file, output_video, stego_key, encryption_type, is_sequential)

        elif choice == '2':
            stego_video = input("Enter the path to the stego video: ")
            output_file = input("Enter the path to save the extracted message: ")
            stego_key = input("Enter the stego key (leave blank for none): ")
            encryption_type = input("Was the message encrypted? (vigenere/none): ").lower()
            is_sequential = input("Was embedding sequential? (yes/no): ").lower() == 'yes'

            extract_message_from_video(stego_video, output_file, stego_key, encryption_type, is_sequential)

        elif choice == '3':
            original_video = input("Enter the path to the original video: ")
            stego_video = input("Enter the path to the stego video: ")
            psnr = calculate_video_psnr(original_video, stego_video)
            print(f"Average PSNR: {psnr:.2f} dB")

        elif choice == '4':
            print("Exiting")
            break

        else:
            print("Invalid choice")
        
main()