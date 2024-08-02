import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np


def encrypt_image(input_path, output_path, key=42):
    img = Image.open(input_path)
    img = img.convert('RGB')
    img_data = np.array(img)

    # Encrypt the image
    encrypted_data = img_data ^ key
    encrypted_img = Image.fromarray(encrypted_data.astype('uint8'))
    encrypted_img.save(output_path)


def decrypt_image(input_path, output_path, key=42):
    img = Image.open(input_path)
    img = img.convert('RGB')
    img_data = np.array(img)

    # Decrypt the image
    decrypted_data = img_data ^ key
    decrypted_img = Image.fromarray(decrypted_data.astype('uint8'))
    decrypted_img.save(output_path)


def select_image(action):
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if file_path:
        try:
            key = int(key_entry.get())
            if action == 'encrypt':
                output_path = filedialog.asksaveasfilename(defaultextension=".jpg",
                                                           filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
                if output_path:
                    encrypt_image(file_path, output_path, key)
                    messagebox.showinfo("Success", "Image encrypted successfully!")
            elif action == 'decrypt':
                output_path = filedialog.asksaveasfilename(defaultextension=".jpg",
                                                           filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
                if output_path:
                    decrypt_image(file_path, output_path, key)
                    messagebox.showinfo("Success", "Image decrypted successfully!")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid integer for the key.")


app = tk.Tk()
app.title("Image Encryption/Decryption Tool")

frame = tk.Frame(app)
frame.pack(pady=20)

key_label = tk.Label(frame, text="Enter Key:")
key_label.grid(row=0, column=0, padx=10)

key_entry = tk.Entry(frame)
key_entry.grid(row=0, column=1, padx=10)

encrypt_button = tk.Button(frame, text="Encrypt Image", command=lambda: select_image('encrypt'))
encrypt_button.grid(row=1, column=0, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt Image", command=lambda: select_image('decrypt'))
decrypt_button.grid(row=1, column=1, pady=10)

app.mainloop()
