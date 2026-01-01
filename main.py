import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import os

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
# from Crypto.Random import get_random_bytes

# import hashlib # using SHA-256

# -- encrypt key KEY setup --
# user input the password -> hash(password) to obatin a 256 bit output 
KEY = b''   # key size 256 bits


# --- E/D Functions ---

def encrypt(target_file,mode):
    # get plaintext
    with open(target_file, 'rb') as f:
        plaintext = f.read()

    # nonce pycryptodome CCM 會自動產生 random 11 bytes 
    if mode == 'CCM encrypt':
        cipher = AES.new(KEY, AES.MODE_CCM)
    else:
        cipher = AES.new(KEY, AES.MODE_GCM)
    
    # ciphertext, tag (MAC)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext) # return a tuple (ciphertext, tag)
    
    # nonce + tag + ciphertext
    # pycryptodome CCM 預設 nonce 長度 11 bytes, Tag  16 bytes
    # pycryptodome GCM 預設 nonce 長度 16 bytes, Tag  16 bytes
    if mode == 'CCM encrypt':
        output_file = target_file + ".ccm"
    else:
        output_file = target_file + ".gcm"
    with open(output_file, 'wb') as f:
        # 解密時要照相同順序
        f.write(cipher.nonce) # nonce
        f.write(tag)          # tag (MAC)
        f.write(ciphertext)   # ciphertext

    messagebox.showinfo("successful", f"{mode} complete \nFile save as: {output_file}")

def decrypt(target_file,mode):
    try:
        # get ciphertext
        with open(target_file, 'rb') as f:
            # 注意順序
            if mode == 'CCM decrypt':
                nonce = f.read(11) # CCM 預設 nonce 11 bytes
            else:
                nonce = f.read(16) # GCM 預設 nonce 16 bytes
            tag = f.read(16)   # tag (16 bytes)
            ciphertext = f.read() # ciphertext

        # decrypt 要給定 ciphertext 的那組 tag 來做驗證
        if mode == 'CCM decrypt':
            cipher = AES.new(KEY, AES.MODE_CCM, nonce=nonce)
        else :
            cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        
        # decrypt ciphertext and verify tag (MAC) 
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        filename_without_enc_ext = os.path.splitext(target_file)[0]
        root_name, original_ext = os.path.splitext(filename_without_enc_ext)
        if mode == 'CCM decrypt':
            output_file = f"{root_name}_ccm_decrypted{original_ext}"
        else :
            output_file = f"{root_name}_gcm_decrypted{original_ext}"
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("successful", f"{mode} complete \nFile saved as: {output_file}")
        
    except ValueError:
        messagebox.showerror("Error", "MAC Check Failed \nThe file may have been altered or the key may be incorrect.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def select_file():
    file_path = filedialog.askopenfilename(
        title="select a file",
        initialdir=os.getcwd() 
    )
    
    if file_path:
        file_path_var.set(file_path)
    else:
        pass

def run_crypto():
    # -- get file --
    target_file = file_path_var.get()
    
    selected_mode = combo_mode.get() # 加解密模式
    password = password_entry.get() # 使用者輸入密碼

    # -- basic checking --
    if not password:
        messagebox.showwarning("error", "No password entry")
        return
    if target_file == "Files not yet selected" or not target_file:
        messagebox.showwarning("warning", "Please select a file first")
        return
    if not selected_mode:
        messagebox.showwarning("warning", "Please select an Enctypt/Decrypt mode")
        return
    
    # -- hash(password)  (SHA-256) --
    hash_key = SHA256.new()
    hash_key.update(password.encode('utf-8'))
    global KEY # 宣告全域變數
    KEY = hash_key.digest()

    # -- AES function call --
    try:
        if selected_mode == "CCM encrypt" or selected_mode == "GCM encrypt":
            encrypt(target_file,selected_mode) 
            
        elif selected_mode == "CCM decrypt" or selected_mode == "GCM decrypt":
            decrypt(target_file,selected_mode)
        
    except Exception:
        # 非預期錯誤
        messagebox.showerror("System Error", f"{str(Exception)}")


# --- tkinter window ---
window = tk.Tk()
window.title('AES CCM/GCM ')
window.geometry('800x450')
window.resizable(False, False)

file_path_var = tk.StringVar()
file_path_var.set("Files not yet selected")

tk.Label(window, text="AES CCM/GCM Encrypt/Decrypt tool", font=("Arial", 16, "bold")).pack(pady=20)

file_frame = tk.Frame(window)
file_frame.pack(pady=10)

btn_select = tk.Button(
    file_frame, 
    text="select file", 
    font=("Arial", 12), 
    command=select_file, 
    width=15
)
btn_select.pack(side=tk.LEFT, padx=10)

lbl_path = tk.Label(
    file_frame, 
    textvariable=file_path_var, 
    font=("Arial", 10), 
    bg="lightgray", 
    width=50, 
    anchor="w",
    relief="sunken"
)
lbl_path.pack(side=tk.LEFT)

# mode selection
tk.Label(window, text="Modes:", font=("Arial", 12)).pack(pady=(20, 5))
combo_mode = ttk.Combobox(
    window, 
    font=("Arial", 12),
    state="readonly", 
    width=30
)
combo_mode['values'] = ("CCM encrypt", "CCM decrypt", "GCM encrypt", "GCM decrypt")
combo_mode.current(0)
combo_mode.pack(pady=5)


# user password input
tk.Label(window, text="Password:", font=("Arial", 12)).pack(pady=(20, 5))
password_entry = tk.Entry(
    window, 
    font=("Arial", 12),
    show='*',    # hide input string
    width=30
)
password_entry.pack(pady=5)

# run
btn_run = tk.Button(
    window, 
    text="RUN", 
    font=("Arial", 12, "bold"), 
    bg="#dddddd",
    command=run_crypto, 
    width=12,
    height=2
)
btn_run.pack(pady=40)


# tkinter window mainloop 
window.mainloop()