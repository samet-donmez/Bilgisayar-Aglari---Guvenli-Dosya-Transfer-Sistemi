import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import time

class Receiver:
    def __init__(self):
        self.key_chunks = []
        self.file_chunks = []
        self.listen_ip = "127.0.0.1"
        self.key_port = 10001
        self.file_port = 20001
        self.buffer_size = 4096 # Soket için tampon boyutu
        
        # Soketleri oluştur
        self.key_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.file_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Portları bağla
        self.key_socket.bind((self.listen_ip, self.key_port))
        self.file_socket.bind((self.listen_ip, self.file_port))
        
        

    def receive_data(self, sock, expected_total_size=None):
        chunks = []
        received_size = 0
        start_time = time.time()
        
        print(f"DEBUG: {sock.getsockname()[1]} portundan veri bekleniyor...")
        
        # İlk paketi bekle (blocking)
        sock.settimeout(5) # İlk paket için kısa bir timeout
        try:
            data, addr = sock.recvfrom(self.buffer_size)
            chunks.append(data)
            received_size += len(data)
            print(f"DEBUG: {sock.getsockname()[1]} portundan ilk parça alındı, boyut: {len(data)} byte")
        except socket.timeout:
            print(f"HATA: {sock.getsockname()[1]} portundan ilk paket alınamadı (timeout).")
            return None

       
        
        # Göndericinin tüm paketleri göndermesi için kısa bir süre daha dinleyelim
        sock.settimeout(0.5) # Her paket arası kısa bir timeout
        while True:
            try:
                data, addr = sock.recvfrom(self.buffer_size)
                chunks.append(data)
                received_size += len(data)
                print(f"DEBUG: {sock.getsockname()[1]} portundan ek parça alındı, boyut: {len(data)} byte")
            except socket.timeout:
                # Timeout olduğunda, göndericinin göndermeyi bitirdiğini varsayabiliriz
                print(f"DEBUG: {sock.getsockname()[1]} portunda veri alımı tamamlandı (timeout).")
                break
            except Exception as e:
                print(f"HATA: {sock.getsockname()[1]} portundan veri alırken hata: {e}")
                break
        
        return b"".join(chunks)

    def decrypt_data(self, encrypted_key, encrypted_file):
        try:
            # Anahtarı çöz
            print(f"DEBUG: Birleştirilmiş şifreli AES anahtarı boyutu: {len(encrypted_key)} byte")
            with open("keys/private_key.pem", "rb") as f:
                private_key = RSA.import_key(f.read())
            


            #-------------------------------------------------------------------------------------------------
            aes_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
            print(f"\nAES anahtarı çözüldü: {aes_key.hex()}")
            #-------------------------------------------------------------------------------------------------
            


            # Dosyayı çöz
            print(f"DEBUG: Birleştirilmiş şifreli dosya verisi boyutu: {len(encrypted_file)} byte")
            
            if len(encrypted_file) < 32:
                raise ValueError(f"Şifreli dosya verisi çok kısa: {len(encrypted_file)} byte. En az 32 byte olmalı (nonce + tag).")

            nonce, tag, ciphertext = encrypted_file[:16], encrypted_file[16:32], encrypted_file[32:]
            
            print(f"DEBUG: Nonce boyutu: {len(nonce)}, Tag boyutu: {len(tag)}, Ciphertext boyutu: {len(ciphertext)}")
            

            #-------------------------------------------------------------------------------------------------
            cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Dosyayı kaydet
            with open("alinan_dosya.txt", "wb") as f:
                f.write(decrypted)
            #-------------------------------------------------------------------------------------------------

            print("Dosya başarıyla kaydedildi!")
            return True
        
        except Exception as e:
            print(f"\nHATA: Şifre çözme veya dosya kaydetme hatası: {str(e)}")
            return False

    def run(self):
        print(f"Alıcı başlatıldı. Dinlenen IP: {self.listen_ip}, Portlar: {self.key_port}, {self.file_port}")
        print("Paketler bekleniyor...\n")
        
        # Anahtar paketini al
        received_encrypted_key = self.receive_data(self.key_socket)
        if received_encrypted_key is None:
            print("\nHATA: AES anahtarı alınamadı!")
            return
        
        # Dosya paketlerini al
        received_encrypted_file = self.receive_data(self.file_socket)
        if received_encrypted_file is None:
            print("\nHATA: Dosya verisi alınamadı!")
            return

        # Verileri çöz ve kaydet
        if not self.decrypt_data(received_encrypted_key, received_encrypted_file):
            print("\nÇözme işlemi başarısız oldu")

        # Soketleri kapat
        self.key_socket.close()
        self.file_socket.close()
        print("Alıcı sonlandırıldı.")

if __name__ == "__main__":
    receiver = Receiver()
    receiver.run()
