from Crypto.PublicKey import RSA
import os

def generate_keys():
    # Dizin yoksa oluştur
    os.makedirs("keys", exist_ok=True)
    
    # RSA anahtarı oluştur
    key = RSA.generate(2048)
    
    # Anahtarları kaydet
    with open("keys/private_key.pem", "wb") as f:
        f.write(key.export_key())
    
    with open("keys/receiver_public_key.pem", "wb") as f:
        f.write(key.publickey().export_key())
    
    print("Anahtar çifti 'keys' klasörüne kaydedildi.")

if __name__ == "__main__":
    generate_keys()