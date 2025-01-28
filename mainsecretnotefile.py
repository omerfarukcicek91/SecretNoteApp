import base64
from tkinter import *
from tkinter import filedialog
from PIL import Image, ImageTk
import tkinter.ttk as ttk
from cryptography.fernet import Fernet
import os
import hashlib

key_file = "encryption_key.key"

def create_and_save_key(user_password):
    encryption_key = Fernet.generate_key()  # Generate a random Fernet key
    hashed_password = hashlib.sha256(user_password.encode()).digest()[:32]  # Hash the password and reduce to 32 bytes
    hashed_password_base64 = base64.urlsafe_b64encode(hashed_password)  # Convert to Base64 format
    cipher = Fernet(hashed_password_base64)
    encrypted_key = cipher.encrypt(encryption_key)

    with open(key_file, "wb") as file:
        file.write(encrypted_key)
    return encryption_key


def load_key(user_password):
    if not os.path.exists(key_file):
        return None
    try:
        with open(key_file, "rb") as file:
            encrypted_key = file.read()
        hashed_password = hashlib.sha256(user_password.encode()).digest()[:32]
        hashed_password_base64 = base64.urlsafe_b64encode(hashed_password)  # Convert to Base64 format
        cipher = Fernet(hashed_password_base64)
        return cipher.decrypt(encrypted_key)
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

def load_or_create_key():
    if os.path.exists(key_file):
        return None  # If key file already exists, ask user for the password
    else:
        def save_password():
            user_password = pass_entry.get()
            if user_password:
                create_and_save_key(user_password)
                pass_entry_window.destroy()  # Close the window
            else:
                error_label.config(text="Password cannot be empty!", fg="red")

        # Create a window to ask the user to save the password for the key
        pass_entry_window = Tk()
        pass_entry_window.configure(padx=10, pady=10, bg="white")
        pass_entry_window.wm_title("Define Encryption Password")

        pass_label = Label(pass_entry_window, text="Enter a password to secure your key:", bg="white")
        pass_label.pack(pady=5)

        pass_entry = Entry(pass_entry_window, show="*", width=30)
        pass_entry.pack(pady=5)

        error_label = Label(pass_entry_window, text="", bg="white")
        error_label.pack(pady=5)

        pass_entry_save_button = ttk.Button(pass_entry_window, text="Save Password", command=save_password)
        pass_entry_save_button.pack(pady=10)

        pass_entry_window.mainloop()  # This line waits for the window to close

        return None  # No key created yet, so return None



passkey = load_or_create_key()
cipher_suite = Fernet(passkey) if passkey else None

secret_note_window = Tk()
secret_note_window.title("SECRET NOTE")
secret_note_window.config(bg="light grey", padx=20, pady=10, width=350, height=600)
FONT = ('Arial', 15, 'bold')

img = Image.open("ts.png")
resized_image = img.resize((150, 150))
image = ImageTk.PhotoImage(resized_image)
image_label = Label(image=image, bg="light grey", fg="grey")
image_label.config(padx=20, pady=20)
image_label.pack()

note_title = Label(text="Enter Your Title", bg="light grey")
note_title.config(font=FONT, padx=5, pady=5)
note_title.pack()

note_entry = Entry(background="white", width=40)
note_entry.config()
note_entry.pack()

secret_title = Label(text="Enter Your Secret", bg="light grey")
secret_title.config(font=FONT, padx=5, pady=5)
secret_title.pack()

secret_text = Text(width=50, height=20)
secret_text.pack()

master_key_title = Label(text="Enter Master Key")
master_key_title.config(font=FONT, bg="light grey")
master_key_title.pack()

master_key_entry = Entry(background="white", width=40)
master_key_entry.config()
master_key_entry.pack()

style_button = ttk.Style()
style_button.configure("Custom.TButton", background="light grey", foreground="black")

def save_master_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    with open("encryption_key.key", "w") as file:
        file.write(hashed_password)

def check_master_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if os.path.exists("encryption_key.key"):
        with open("encryption_key.key", "r") as file:
            stored_password = file.read()
            return hashed_password == stored_password
    return False

def save_button_clicked():
    master_key_check = master_key_entry.get()
    encryption_key = load_key(master_key_check)

    if encryption_key:
        cipher_suite = Fernet(encryption_key)
        input1 = note_entry.get()  # Title
        input2 = secret_text.get("1.0", END).strip()  # Secret message
        file_name = "myNotes.txt"

        if not input1:
            error_popup("Please Enter Your Secret Header")
        elif not input2:
            error_popup("Please Enter Your Secret")
        else:
            try:
                # Encryption process
                encrypted_text = cipher_suite.encrypt(input2.encode())

                # Open or create the file and write the encrypted text
                with open(file_name, "a") as f:
                    f.write(f"{input1}\n")  # Title
                    f.write(encrypted_text.decode() + "\n\n")  # Encrypted message
                note_entry.delete(0, END)
                secret_text.delete("1.0", END)
                master_key_entry.delete(0, END)
                print("Note saved and encrypted successfully!")
            except Exception as e:
                error_popup(f"Error saving note: {e}")
    elif not master_key_check:
        error_popup("Please Enter Password")
    else:
        error_popup("Incorrect Password")


def error_popup(error_message):
    error_window = Toplevel()
    error_window.wm_title("Warning!!")
    error_window.configure(bg="white")

    err_img = Image.open("error-image.png")
    resized_err_image = err_img.resize((50, 50))
    error_image = ImageTk.PhotoImage(resized_err_image)
    error_window.error_image = error_image

    error_image_label = Label(error_window, image=error_image, bg="white")
    error_image_label.pack(pady=(10, 0))

    error_label = Label(error_window, text=error_message, bg="white")
    error_label.pack(pady=(10, 20))

    close_button = ttk.Button(error_window, text="OK", command=error_window.destroy, style="Custom.TButton")
    close_button.pack(pady=(10, 20))

    error_window.mainloop()

def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
    if not file_path:
        return None
    with open(file_path, 'rb') as file:
        return file.read()

def save_file(content, mode='wb'):
    file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")])
    if not file_path:
        return
    with open(file_path, mode) as file:
        file.write(content)

def encrypt(status_label=None):
    try:
        content = load_file()
        if content:
            cipher_text = cipher_suite.encrypt(content)
            save_file(cipher_text)
            if status_label:
                status_label.config(text="File encrypted successfully!")
    except Exception as e:
        if status_label:
            status_label.config(text=f"Encryption failed: {e}")
        print(f"Error during encryption: {e}")

def decrypt(status_label=None):
    try:
        # If cipher_suite is None, inform the user that the key was not loaded properly
        if cipher_suite is None:
            if status_label:
                status_label.config(text="Cipher suite is not initialized. Please load the key first.")
            return

        # Get the encrypted text from secret_text and decrypt it
        encrypted_text = secret_text.get("1.0", END).strip()
        if encrypted_text:
            try:
                # Convert the encrypted text to a byte array
                encrypted_bytes = encrypted_text.encode("utf-8")

                # Decrypt the text
                plain_text = cipher_suite.decrypt(encrypted_bytes).decode("utf-8")

                # Write the decrypted text back to secret_text
                secret_text.delete("1.0", END)  # Clear existing content
                secret_text.insert("1.0", plain_text)  # Add decrypted text

                if status_label:
                    status_label.config(text="Decryption successful!")
            except Exception as e:
                if status_label:
                    status_label.config(text=f"Decryption failed: {e}")
                print(f"Error during decryption: {e}")
        else:
            if status_label:
                status_label.config(text="No encrypted text found to decrypt.")
    except Exception as e:
        if status_label:
            status_label.config(text=f"Decryption failed: {e}")
        print(f"Error during decryption: {e}")


save_button = ttk.Button(text="Save & Encrypt", command=save_button_clicked, style="Custom.TButton")
save_button.config()
save_button.pack()

decrypt_button = ttk.Button(text="Decrypt", command=decrypt, style="Custom.TButton")
decrypt_button.config()
decrypt_button.pack()

secret_note_window.mainloop()
