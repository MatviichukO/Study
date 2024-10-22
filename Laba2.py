import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

# Генерація ключа
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 біт для AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

# Шифрування даних
def encrypt_file(input_file, output_file, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = generate_key(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # Додавання вирівнювання
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Додавання MAC
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    mac = h.finalize()

    with open(output_file, 'wb') as f_out:
        f_out.write(salt + iv + mac + encrypted_data)

# Дешифрування даних
def decrypt_file(input_file, output_file, password):
    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    salt, iv, mac, encrypted_data = data[:16], data[16:32], data[32:64], data[64:]

    key = generate_key(password.encode(), salt)

    # Перевірка MAC
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(encrypted_data)
    try:
        h.verify(mac)
    except:
        messagebox.showerror("Помилка")
        return

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Видалення вирівнювання
    unpadder = padding.PKCS7(128).unpadder()
    try:
        data = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError:
        messagebox.showerror("Помилка")
        return

    with open(output_file, 'wb') as f_out:
        f_out.write(data)

    messagebox.showinfo("Успіх")

# Графічний інтерфейс
def select_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def encrypt_action():
    input_file = input_entry.get()
    output_file = output_entry.get()
    password = password_entry.get()

    if not input_file or not output_file or not password:
        messagebox.showerror("Помилка", "Помилка x2")
        return

    encrypt_file(input_file, output_file, password)
    messagebox.showinfo("Успіх", "Успіх x2")

def decrypt_action():
    input_file = input_entry.get()
    output_file = output_entry.get()
    password = password_entry.get()

    if not input_file or not output_file or not password:
        messagebox.showerror("Помилка" "Помилка x2")
        return

    decrypt_file(input_file, output_file, password)

# Створення головного вікна
root = tk.Tk()
root.title("Interface")

# Поля для введення
tk.Label(root, text="Вхідний файл:").grid(row=0, column=0, padx=10, pady=5)
input_entry = tk.Entry(root, width=50)
input_entry.grid(row=0, column=1, padx=10, pady=5)
tk.Button(root, text="Обрати файл", command=lambda: select_file(input_entry)).grid(row=0, column=2, padx=10, pady=5)

tk.Label(root, text="Вихідний файл:").grid(row=1, column=0, padx=10, pady=5)
output_entry = tk.Entry(root, width=50)
output_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, text="Пароль:").grid(row=2, column=0, padx=10, pady=5)
password_entry = tk.Entry(root, width=50, show="*")
password_entry.grid(row=2, column=1, padx=10, pady=5)

# Кнопки
tk.Button(root, text="Зашифрувати", command=encrypt_action).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Дешифрувати", command=decrypt_action).grid(row=3, column=1, padx=10, pady=10)

root.mainloop()
