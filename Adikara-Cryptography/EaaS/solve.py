from pwn import *
import string

# Fungsi untuk connect ke server
def connect():
    return remote('117.53.47.247', 60010)

# Fungsi untuk melakukan enkripsi dengan mengirimkan pesan ke server
def encrypt(r, message):
    r.sendlineafter(b"Enter your choice: ", b"1") # Pilih opsi enkkripsi
    r.sendlineafter(b"Enter your message: ", message) # Kirim pesan yang akan dienkripsi
    response = r.recvline().decode().strip() # Terima respon dari server
    return bytes.fromhex(response.split("Encrypted: ")[1]) # Convert hex ke bytes

# Fungsi untuk nyari ukuran block dengan menambah input hingga panjang outputnya berubah
def find_block_size():
    r = connect()
    base_length = len(encrypt(r, b"")) # Dapatkan panjang output awal
    i = 1
    while True:
        length = len(encrypt(r, b"A" * i)) # Coba dengan input yang lebih panjang
        if length > base_length: # Ngecek jika panjang berubah
            r.close()
            return length - base_length # Kembalikan selisih sebagai block size
        i += 1

# Fungsi untuk mendapatkan flag
def leak_flag():
    r = connect()
    block_size = 16  # Block size AES adalah 16 bytes
    known_flag = b""
    
    # Hitung panjang padding yang diperlukan agar byte flag yang dicari berada di akhir block
    while True:
        pad_length = (block_size - (len(known_flag) % block_size) - 1)
        padding = b"A" * pad_length
        
        # Dapatkan block target yang berisi padding + 1 byte flag yang tidak diketahui
        target = encrypt(r, padding)
        target_block_index = (len(padding) + len(known_flag)) // block_size
        target_block = target[target_block_index * block_size:(target_block_index + 1) * block_size]
        
        found = False
        # Coba semua kemungkinan byte yang printable
        for c in string.printable.encode():
            test_input = padding + known_flag + bytes([c]) # Gabungkan padding + flag yang diketahui + byte yang dicoba
            result = encrypt(r, test_input)
            test_block = result[target_block_index * block_size:(target_block_index + 1) * block_size]
            
            # Jika block sama dengan target, berarti byte ditemukan
            if test_block == target_block:
                known_flag += bytes([c])
                print(f"Found byte: {bytes([c])} | Current flag: {known_flag}")
                found = True
                break
        
        # Jika tidak ada byte yang cocok, berarti flag sudah lengkap
        if not found:
            break
    
    r.close()
    return known_flag

if __name__ == "__main__":
    print("Starting exploit...")
    flag = leak_flag()
    print(f"\nFinal flag: {flag}")
