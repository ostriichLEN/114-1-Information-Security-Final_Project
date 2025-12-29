import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import hashlib 

# -- 使用者輸入密碼產生並輸入進 hash function --

# -- encrypt key KEY setup --
# user input the password -> hash(password) to obatin a 128 bit output 
KEY = b'1234567890123456'   # key size = 16 bytes = 128 bits


# --- E/D Functions ---

def call_ccm_encrypt(target_file):
    # get plaintext
    with open(target_file, 'rb') as f:
        plaintext = f.read()

    # nonce pycryptodome CCM 會自動產生 random 11 bytes 
    cipher = AES.new(KEY, AES.MODE_CCM)
    
    # ciphertext, tag (MAC)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # nonce + tag + ciphertext
    # pycryptodome CCM 預設 nonce 長度 11 bytes, Tag  16 bytes
    output_file = target_file + ".ccm"
    with open(output_file, 'wb') as f:
        # 解密時要照相同順序
        f.write(cipher.nonce) # nonce
        f.write(tag)          # tag (MAC)
        f.write(ciphertext)   # ciphertext

    messagebox.showinfo("successful", f"Encrypt complete \nFile save as: {output_file}")

def call_ccm_decrypt(target_file):
    try:
        # get ciphertext
        with open(target_file, 'rb') as f:
            # 注意順序
            nonce = f.read(11) # nonce (11 bytes)
            tag = f.read(16)   # tag (16 bytes)
            ciphertext = f.read() # ciphertext

        # decrypt 要給定 ciphertext 的那組 tag 來做驗證
        cipher = AES.new(KEY, AES.MODE_CCM, nonce=nonce)
        
        # decrypt ciphertext and verify tag (MAC) 
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        filename_without_enc_ext = os.path.splitext(target_file)[0]
        root_name, original_ext = os.path.splitext(filename_without_enc_ext)
        output_file = f"{root_name}_ccm_decrypted{original_ext}"
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("successful", f"Decrypt complete \nFile saved as: {output_file}")
        
    except ValueError:
        messagebox.showerror("Error", "MAC Check Failed \nThe file may have been altered or the key may be incorrect.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def call_gcm_encrypt(target_file):
    # get plaintext
    with open(target_file, 'rb') as f:
        plaintext = f.read()

    # nonce pycryptodome GCM 會自動產生 random 16 bytes 
    cipher = AES.new(KEY, AES.MODE_GCM)
    
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    # Nonce + Tag + Ciphertext
    output_file = target_file + ".gcm"
    with open(output_file, 'wb') as f:
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    messagebox.showinfo("successful", f"Encrypt complete \nFile save as: {output_file}")

def call_gcm_decrypt(target_file):
    try:
        # get ciphertext
        with open(target_file, 'rb') as f:
            nonce = f.read(16) # pycryptodome GCM 預設 nonce 16 bytes
            tag = f.read(16)
            ciphertext = f.read()

        # decrypt 要給定 ciphertext 的那組 tag 來做驗證
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        
        # decrypt ciphertext and verify tag (MAC)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        filename_without_enc_ext = os.path.splitext(target_file)[0]
        root_name, original_ext = os.path.splitext(filename_without_enc_ext)
        output_file = f"{root_name}_gcm_decrypted{original_ext}"
        with open(output_file, 'wb') as f:
            f.write(plaintext)

        messagebox.showinfo("successful", f"Decrypt complete \nFile saved as: {output_file}")

    except ValueError:
        messagebox.showerror("error", "MAC Check Failed \nThe file may have been altered or the key may be incorrect.")
    except Exception as e:
        messagebox.showerror("error", str(e))



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
    # get path
    target_file = file_path_var.get()
    
    
    selected_mode = combo_mode.get() # 加解密模式
    password = password_entry.get() # 使用者輸入密碼

    if not password:
        messagebox.showwarning("error", "No password entry")
        return
    
    # basic checking
    if target_file == "Files not yet selected" or not target_file:
        messagebox.showwarning("warning", "Please select a file first")
        return
    
    if not selected_mode:
        messagebox.showwarning("warning", "Please select an Enctypt/Decrypt mode")
        return
    
    hash_key = hashlib.sha256()
    hash_key.update(password.encode('utf-8'))
    global KEY # 宣告全域變數
    KEY = hash_key.digest()

    # -- AES function call --
    try:
        if selected_mode == "CCM encrypt":
            call_ccm_encrypt(target_file) 
            
        elif selected_mode == "CCM decrypt":
            call_ccm_decrypt(target_file)
            
        elif selected_mode == "GCM encrypt":
            call_gcm_encrypt(target_file)
            
        elif selected_mode == "GCM decrypt":
            call_gcm_decrypt(target_file)
        
    except Exception as e:
        # 非預期錯誤
        messagebox.showerror("System Error", f"{str(e)}")


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