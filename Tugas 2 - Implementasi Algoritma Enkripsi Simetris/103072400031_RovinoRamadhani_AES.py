"""Praktikum Keamanan Siber: enkripsi dan dekripsi teks AES-256-GCM.

Instal dependensi: pip install cryptography
Jalankan: python 103072400031_RovinoRamadhani_AES.py
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def turunkan_kunci(kata_sandi: str, salt: bytes) -> bytes:
    """Turunkan kunci AES-256 (32 byte) dari kata sandi dan salt."""
    return hashlib.pbkdf2_hmac(
        "sha256", kata_sandi.encode("utf-8"), salt, 200_000, dklen=32
    )


def enkripsi(teks: str, kata_sandi: str) -> str:
    """Enkripsi teks UTF-8 dan kembalikan salt + nonce + ciphertext dalam Base64."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kunci = turunkan_kunci(kata_sandi, salt)
    ciphertext = AESGCM(kunci).encrypt(nonce, teks.encode("utf-8"), None)
    gabungan = salt + nonce + ciphertext
    return base64.b64encode(gabungan).decode("ascii")


def dekripsi(ciphertext_b64: str, kata_sandi: str) -> str:
    """Dekripsi Base64; kegagalan ditangani dengan pesan aman di main()."""
    gabungan = base64.b64decode(ciphertext_b64, validate=True)
    if len(gabungan) < 44:  # salt 16 + nonce 12 + authentication tag 16
        raise ValueError("Ciphertext terlalu pendek")

    salt = gabungan[:16]
    nonce = gabungan[16:28]
    ciphertext = gabungan[28:]
    kunci = turunkan_kunci(kata_sandi, salt)
    plaintext = AESGCM(kunci).decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def main() -> None:
    while True:
        print("\n=== ENKRIPSI SIMETRIS (AES-GCM) ===")
        print("1. Enkripsi teks")
        print("2. Dekripsi teks")
        print("0. Keluar")
        pilihan = input("Pilih menu: ").strip()
        if pilihan == "0":
            print("Program selesai.")
            break
        if pilihan not in {"1", "2"}:
            print("Pilihan menu tidak valid.")
            continue

        pesan = input(
            "Masukkan plaintext: "
            if pilihan == "1" else "Masukkan ciphertext Base64: "
        )
        kata_sandi = input("Masukkan kata sandi: ")
        if not kata_sandi:
            print("Kata sandi tidak boleh kosong.")
            continue

        try:
            if pilihan == "1":
                print("Ciphertext (Base64):", enkripsi(pesan, kata_sandi))
            else:
                print("Plaintext:", dekripsi(pesan, kata_sandi))
        except (InvalidTag, ValueError, UnicodeDecodeError):
            print("Dekripsi gagal: kata sandi atau ciphertext tidak sesuai.")


if __name__ == "__main__":
    main()