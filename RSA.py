# install library jika belum ada, bisa di uncomment.
# %pip install cryptography pandas --quiet

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import pandas as pd

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def encrypt_message(message: str) -> str:
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

def decrypt_message(cipher_hex: str) -> str:
    try:
        ciphertext_bytes = bytes.fromhex(cipher_hex)
        plaintext = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception as e:
        return f"[ERROR] Gagal mendekripsi: {e}"
    
#Mode input manual
def enkripsi_manual():
    print("━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
    plaintext = input("Masukkan pesan yang ingin dienkripsi: ")
    ciphertext_hex = encrypt_message(plaintext)
    print("\nHasil pesan yang sudah dienkripsi (hex):\n", ciphertext_hex)


def dekripsi_manual():
    print("━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
    ciphertext_hex = input("Masukkan ciphertext (hex) yang ingin didekripsi: ")
    plaintext = decrypt_message(ciphertext_hex)
    print("\nHasil pesan yang sudah didekripsi:\n", plaintext)


import pandas as pd
import io
import os

# === Fungsi enkripsi file ===
def enkripsi_file():
    print("━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
    filetype = input("Masukkan jenis file (csv/xlsx): ").strip().lower()

    if filetype == "exit":
        print("\n˙⋆✮ Sampai jumpa lagi! ✮⋆˙")
        return "exit"

    if filetype not in ["csv", "xlsx"]:
        print("[ERROR] Jenis file tidak valid! Pilih antara 'csv' atau 'xlsx'.")
        return None

    filename = input(f"Masukkan nama file {filetype.upper()} (contoh: data.{filetype}): ").strip()

    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' tidak ditemukan di direktori saat ini.")
        return None

    print(f"\n✅ File '{filename}' berhasil ditemukan dan akan diproses!\n")

    # Baca file
    if filetype == "csv":
        df = pd.read_csv(filename)
    else:
        df = pd.read_excel(filename)

    print("\nKolom tersedia:", list(df.columns))
    column = input("Masukkan nama kolom yang ingin dienkripsi (atau ketik 'Exit' untuk batal): ").strip().lower()
    if column.lower() == "exit":
        print("\n˙⋆✮ Proses dibatalkan. Kembali ke menu utama. ✮⋆˙")
        return None

    if column not in df.columns:
        print("[ERROR] Kolom tidak ditemukan!")
        return None

    # Proses enkripsi
    df_result = pd.DataFrame()
    df_result["index"] = df.index
    df_result["encrypted_text"] = df[column].apply(lambda x: encrypt_message(str(x)))

    # Simpan hasil
    base_name, _ = os.path.splitext(filename)
    output_name = f"encrypted_{os.path.basename(base_name)}.{filetype}"
    if filetype == "csv":
        df_result.to_csv(output_name, index=False)
    else:
        df_result.to_excel(output_name, index=False)

    print(f"\n✅ File terenkripsi berhasil disimpan sebagai '{output_name}'!")
    print(f"💾 File tersimpan di direktori: {os.getcwd()}\n")
    return None


# === Fungsi dekripsi file ===
def dekripsi_file():
    print("━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
    filetype = input("Masukkan jenis file terenkripsi (csv/xlsx): ").strip().lower()

    if filetype == "exit":
        print("\n˙⋆✮ Sampai jumpa lagi! ✮⋆˙")
        return "exit"

    if filetype not in ["csv", "xlsx"]:
        print("[ERROR] Jenis file tidak valid! Pilih antara 'csv' atau 'xlsx'.")
        return None

    filename = input(f"Masukkan nama file terenkripsi {filetype.upper()} (contoh: encrypted_data.{filetype}): ").strip()

    if not os.path.exists(filename):
        print(f"[ERROR] File '{filename}' tidak ditemukan di direktori saat ini.")
        return None

    print(f"\n✅ File '{filename}' berhasil ditemukan dan akan diproses!\n")

    # Baca file
    if filetype == "csv":
        df = pd.read_csv(filename)
    else:
        df = pd.read_excel(filename)

    # Proses dekripsi (konversi hex → bytes)
    df_result = pd.DataFrame()
    df_result["index"] = df["index"]
    df_result["decrypted_text"] = df["encrypted_text"].apply(lambda x: decrypt_message(bytes.fromhex(x)))

    base_name, _ = os.path.splitext(filename)
    output_name = f"decrypted_{os.path.basename(base_name)}.{filetype}"
    if filetype == "csv":
        df_result.to_csv(output_name, index=False)
    else:
        df_result.to_excel(output_name, index=False)

    print(f"\n✅ File hasil dekripsi berhasil disimpan sebagai '{output_name}'!")
    print(f"💾 File tersimpan di direktori: {os.getcwd()}\n")
    return None

def main():
    print("˙⋆✮ Selamat datang di aplikasi kriptografi sederhana RSA! ✮⋆˙")
    mode()

def mode():
    while True:
        print("━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
        print("Ketik 'Exit' kapan saja untuk keluar dari program.\n")
        print("Pilih mode input [1/2]:\n")
        print("1. Manual")
        print("2. Dari file (csv/xlsx)\n")

        mode_input = input("Masukkan pilihan mode: ").strip().lower()

        if mode_input == "exit":
            print("\n˙⋆✮ Sampai jumpa lagi! ✮⋆˙")
            break

        elif mode_input in ["1", "2"]:
            result = operasi(mode_input)
            if result == "exit":
                break
        else:
            print("Pilihan mode tidak valid! Coba lagi ya [1/2].")


def operasi(mode_input):
    while True:
        print("\n━━━━━━━━━━━━━━━━━━━━━━━━⊱⋆⊰━━━━━━━━━━━━━━━━━━━━━━━━")
        print("Pilih mode operasi [1/2]:\n")
        print("1. Enkripsi pesan")
        print("2. Dekripsi pesan\n")

        print("Ketik back untuk kembali yaa")
        operasi_input = input("Masukkan pilihan operasi: ").strip().lower()

        if operasi_input == "exit":
            print("\n˙⋆✮ Sampai jumpa lagi! ✮⋆˙")
            return "exit"
        elif operasi_input== "back":
            print("\nKembali ke mode input...")
            return

        if mode_input == "1":  # mode manual
            if operasi_input == "1":
                enkripsi_manual()
                break
            elif operasi_input == "2":
                dekripsi_manual()
                break
            else:
                print("Pilihan operasi tidak valid! Coba lagi ya [1/2].")

        elif mode_input == "2":  # mode file
            if operasi_input == "1":
                result = enkripsi_file()
            elif operasi_input == "2":
                result = dekripsi_file()
            else:
                print("Pilihan operasi tidak valid! Coba lagi ya [1/2].")
                continue

            if result == "exit":
                return "exit"

        else:
            print("Pilihan mode tidak valid!")
            continue

main()
