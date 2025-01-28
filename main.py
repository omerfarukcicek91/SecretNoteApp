from tkinter import *
from tkinter import filedialog
from PIL import Image, ImageTk
import tkinter.ttk as ttk
from cryptography.fernet import Fernet
import os
import hashlib

key_file = "encryption_key.key"

# Anahtarın dosyadan okunması veya oluşturulup saklanması


# Şifreleme anahtarını yükleme veya oluşturma
def load_or_create_key():
    if os.path.exists(key_file):
        with open(key_file, "rb") as file:
            return file.read()
    else:
        def save_password():
            user_password = pass_entry.get()
            if user_password:
                encryption_key = Fernet.generate_key()
                with open(key_file, "wb") as file:
                    file.write(encryption_key)
                pass_entry_window.destroy()  # Şifre penceresini kapat
            else:
                error_label.config(text="Password cannot be empty!", fg="red")

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

        pass_entry_window.mainloop()

        # Anahtarı geri dön
        if os.path.exists(key_file):
            with open(key_file, "rb") as file:
                return file.read()
        else:
            raise Exception("Failed to create key file.")



# Anahtar yükleme veya oluşturma
passkey = load_or_create_key()
cipher_suite = Fernet(passkey)


secret_note_window = Tk()
secret_note_window.title("SECRET NOTE")
secret_note_window.config(bg="light grey",padx=20, pady=10, width=350, height=600)
FONT = ('Arial', 15, 'bold')
#adding image
img = Image.open("ts.png")
resized_image = img.resize((150,150))
image = ImageTk.PhotoImage(resized_image)
image_label = Label(image=image, bg="light grey", fg="grey")
image_label.config(padx=20,pady=20)
image_label.pack()
#first title
note_title = Label(text="Enter Your Title", bg="light grey")
note_title.config(font=FONT,
                  padx=5,pady=5)
note_title.pack()
#first entry
note_entry = Entry(background="white",width=40)
note_entry.config()
note_entry.pack()
#secret entry
secret_title = Label(text="Enter Your Secret", bg="light grey")
secret_title.config(font=FONT,
                  padx=5,pady=5)
secret_title.pack()
#secrettextwindow
secret_text = Text(width=50,height=20)
secret_text.pack()
#masterkeytitle
master_key_title = Label(text="Enter Master Key")
master_key_title.config(font=FONT,bg="light grey")
master_key_title.pack()
#masterkeyentry
master_key_entry = Entry(background="white",width=40)
master_key_entry.config()
master_key_entry.pack()
#buttonstyles
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
    if check_master_password(master_key_check):
        input1 = note_entry.get()
        input2 = secret_text.get("0.0", END)
        file_name = str("myNotes.txt")

        if  input1 == "":
            error_message = "Please Enter Your Secret Header"
            error_popup(error_message)
            print("Please Enter a correct value")
        elif input2 == "":
            error_message = "Please enter your secret"
            error_popup(error_message)
            print("Please Enter a correct value 2")
        else:
            with open(f"{file_name}", "a") as f:
                f.write(f"{input1}\n")
                f.write(f"{input2}\n")
                note_entry.delete(0, END)
                secret_text.delete("0.0", END)
                f.close()
                encrypt()
            master_key_entry.delete(0, END)
    elif master_key_check == "":
        error_message = "Please Enter Password"
        error_popup(error_message)
        print("please enter password")
    else:
        error_message = "Incorrect Password"
        error_popup(error_message)
        print("incorrect Password")

def error_popup(error_message):
    error_window = Toplevel()
    error_window.wm_title("Warning!!")
    error_window.configure(bg="white")
    # adding error image
    err_img = Image.open("error-image.png")
    resized_err_image = err_img.resize((50, 50))
    error_image = ImageTk.PhotoImage(resized_err_image)
    error_window.error_image = error_image

    error_image_label = Label(error_window, image=error_image, bg="white")
    error_image_label.pack(pady=(10, 0))

    error_label = Label(error_window, text=error_message,bg="white")
    error_label.pack(pady=(10, 20))

    close_button = ttk.Button(error_window, text= "OK", command=error_window.destroy, style="Custom.TButton")
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
            cipher_text = cipher_suite.encrypt(content)  # İçeriği şifrele
            save_file(cipher_text)  # Şifrelenmiş içeriği dosyaya kaydet
            if status_label:
                status_label.config(text="File encrypted successfully!")
    except Exception as e:
        if status_label:
            status_label.config(text=f"Encryption failed: {e}")
        print(f"Error during encryption: {e}")

def decrypt(status_label=None):
    try:
        content = load_file()
        if content:
            plain_text = cipher_suite.decrypt(content).decode("utf-8")  # Bytes'ı decode ettik
            save_file(plain_text, mode="w")  # Şifre çözülmüş metni kaydediyoruz
            if status_label:
                status_label.config(text="File decrypted successfully!")
    except Exception as e:
        if status_label:
            status_label.config(text=f"Decryption failed: {e}")
        print(f"Error during decryption: {e}")

#save&encrypt button
save_button = ttk.Button(text="Save & Encrypt",command=save_button_clicked, style="Custom.TButton")
save_button.config()
save_button.pack()
#decrypt button
decrypt_button = ttk.Button(text="Decrypt",command=decrypt,style="Custom.TButton")
decrypt_button.config()
decrypt_button.pack()




secret_note_window.mainloop()