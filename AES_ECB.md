# Memecahkan AES ECB -> blok demi blok
```AES (Advanced Encryption Standard) adalah algoritma enkripsi simetris yang digunakan secara luas dan dapat beroperasi dalam berbagai mode. ECB (Electronic Codebook) adalah salah satu mode operasi paling sederhana untuk AES. Dalam mode ECB, setiap blok plaintext (teks asli) dienkripsi secara terpisah dengan kunci yang sama, dan tidak ada mekanisme umpan balik (feedback mechanism).```

### Berikut adalah penjelasan tinggi tentang cara kerja enskripsi AES ECB:
- **Pembangkitan Kunci (Key Generation)**: Anda mulai dengan memilih kunci enkripsi rahasia.
kunci tersebut harus memiliki panjang tetap (128, 192, atau 256 bit, tergantung pada varian AES).
- **Padding (jika diperlukan)**: Jika plaintext Anda bukan kelipatan dari ukuran blok AES (16 byte), Anda mungkin perlu melakukan padding (pengisian) agar sesuai dengan ukuran blok.
- **Enkripsi Blok:** Plaintext dibagi menjadi blok-blok berukuran tetap (biasanya 16 byte) untuk enkripsi. Setiap blok kemudian dienkripsi dengan algoritma AES menggunakan kunci enkripsi yang sama. Proses ini menghasilkan blok ciphertext (teks sandi).
- **Penggabungan (Concatenation)**: Blok-blok ciphertext yang dihasilkan digabungkan untuk membuat ciphertext akhir.

```
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Kunci rahasia (16, 24, atau 32 byte untuk AES-128, AES-192, atau AES-256)
key = get_random_bytes(16)

# Buat objek cipher AES ECB
cipher = AES.new(key, AES.MODE_ECB)

# Plaintext Anda (harus kelipatan 16 byte dalam mode ECB)
plaintext = b'aditya rahman'

# padding ke kelipatan 16 byte
padded_plaintext = pad(plaintext, AES.block_size)

# Enkripsi plaintext
ciphertext = cipher.encrypt(padded_plaintext)

# Cetak ciphertext
print("Ciphertext:", ciphertext)
```

1. Symmetric Key (Satu Kunci untuk Semua)

    Konsep: Kunci untuk mengunci (enkripsi) dan membuka (dekripsi) adalah sama.

    Analogi: Seperti kunci pintu rumah. Kunci yang dipakai untuk mengunci pintu dari luar, dipakai juga untuk membukanya kembali. Jangan sampai kunci ini hilang atau dicuri!

2. Block Cipher (Potong-Potong Data)

    Konsep: Data yang panjang tidak dienkripsi sekaligus, tapi dipotong-potong menjadi kotak-kotak kecil (blok).

    Aturan Emas AES:

        Ukuran Potongan (Blok) = Selalu 16 Byte (fix, tidak bisa ditawar).

        Angka 128/192/256 = Ukuran Kunci (seberapa rumit kuncinya), bukan ukuran potongannya.

3. Mode Operasi (Cara Mengacak) Ibarat cara kita menyusun potongan-potongan tadi:

    ECB (Electronic Codebook) - Si Polos

        Setiap potongan diacak sendiri-sendiri tanpa peduli temannya.

        Kelemahan: Kalau ada dua potongan isinya sama (misal: "AAAA"), hasil acakannya juga pasti sama. Pola data masih kelihatan. Tidak aman.

    CBC (Cipher Block Chaining) - Si Rantai

        Saling nyambung. Hasil acakan potongan pertama dipakai untuk mengacak potongan kedua, dan seterusnya.

        Kelebihan: Walaupun isinya sama ("AAAA"), hasil akhirnya akan beda total karena efek berantai ini. Lebih aman.

4. IV (Initialization Vector) - Bumbu Awal

    Konsep: Karena CBC itu berantai, potongan pertama butuh "lawan main" untuk memulai rantai (karena belum ada potongan sebelumnya).

    Fungsi: Angka acak (random) yang ditambahkan di awal supaya hasil enkripsi selalu unik, meskipun pesan dan kuncinya sama.

5. Logika Enkripsi (Bukan Matematika Biasa)

    Konsep: Enkripsi bukan sekadar 1 + 1 = 2.

    Analogi: Bayangkan Blender. Plaintext (buah) dimasukkan, ditambah Key (pisau blender), lalu diputar berkali-kali (ronde) sampai hancur lebur menjadi Jus (Ciphertext). Mustahil membalikkan jus menjadi buah utuh tanpa cara (kunci) yang tepat.