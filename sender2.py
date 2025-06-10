import socket
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import time
import os

class Sender:
    def __init__(self):
        self.target_ip = "127.0.0.1"
        self.key_port = 10001
        self.file_port = 20001
        self.key_path = "keys/receiver_public_key.pem"
        self.test_file = "test_dosyasi.txt"
        self.chunk_size = 1024 # UDP paket boyutu
        
        # Test dosyası oluştur
        self.create_test_file()

        # Soket oluştur
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    def create_test_file(self):
        if not os.path.exists(self.test_file):
            with open(self.test_file, "wb") as f:
                f.write(b"Bu bir test dosyasidir. " * 50)
            print(f"Test dosyasi olusturuldu: {self.test_file}")

    def encrypt_file(self, file_path, aes_key):
        with open(file_path, "rb") as f:
            data = f.read()
        
        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def send_data(self, data, dst_port):
        chunks = [data[i:i+self.chunk_size] for i in range(0, len(data), self.chunk_size)]
        
        print(f"DEBUG: {dst_port} portuna gönderilecek toplam {len(data)} byte, {len(chunks)} parça halinde.")
        
        for i, chunk in enumerate(chunks):
            self.udp_socket.sendto(chunk, (self.target_ip, dst_port))
            print(f"DEBUG: {dst_port} portuna {i+1}/{len(chunks)} parça gönderildi, boyut: {len(chunk)} byte")
            time.sleep(0.01)  # Paketler arası bekleme
        
        print(f"{len(chunks)} paket {dst_port} portuna gönderildi")

    def run(self):
        # Public key yükle
        with open(self.key_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        
        # AES anahtarı oluştur ve şifrele
        aes_key = get_random_bytes(32)  # 256-bit
        encrypted_key = PKCS1_OAEP.new(public_key).encrypt(aes_key)
        print(f"DEBUG: Oluşturulan şifreli AES anahtarı boyutu: {len(encrypted_key)} byte")
        
        # Dosyayı şifrele
        encrypted_file = self.encrypt_file(self.test_file, aes_key)
        print(f"DEBUG: Oluşturulan şifreli dosya verisi boyutu: {len(encrypted_file)} byte")
        
        # Gönderim
        print("\nAES anahtarı gönderiliyor...")
        self.send_data(encrypted_key, self.key_port)
        
        print("\nŞifrelenmiş dosya gönderiliyor...")
        self.send_data(encrypted_file, self.file_port)
        
        print("\nGönderim tamamlandı!")

        # Soketi kapat
        self.udp_socket.close()
        print("Gönderici sonlandırıldı.")

if __name__ == "__main__":
    sender = Sender()
    sender.run()
