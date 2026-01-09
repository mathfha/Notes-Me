# Apa itu Stack?
- Secara bahasa, `Stack` berarti tumpukan. Bayangkan tumpukan piring di sebuah prasmanan atau tumpukan buku di meja.
- Konsep utamanya adalah `LIFO` (Last In, First Out). Artinya, data yang terakhir dimasukkan adalah data yang pertama kali dikeluarkan.

## Analogi dalam kehidupan sehari-hari:
1. Kamu menaruh Piring A di meja.
2. Kamu menaruh Piring B di atas Piring A.
3. Kamu menaruh Piring C di atas Piring B.
4. Jika kamu ingin mengambil piring, piring mana yang diambil duluan? Pasti kamu akan menjawab Piring C (yang paling terakhir di taruh)

# Kenapa harus ada Stack?
```Stack diciptakan untuk mengelola data secara teratur ketika urutan eksekusi harus dibalik atau diingat. Stack sangat efisien karena kita hanya fokus pada satu ujung saja (bagian atas atau Top).```
Kapan Stack berfungsi dalam dunia nyata?
- Fitur "Undo." (Ctrl+Z): Komputer menyimpan setiap perubahanmu dalam sebuah stack. Saat kamu undo. ia mengambil perubahan paling terakhir untuk dibatalkan.
- Navigasi Browser: Saat kamu klik tombol "Back", browser mengambil histori halaman terakhir yang kamu buka dari stack.
- Pemanggilan Fungsi (Call Stack): Di dalam bahasa pemrograman, saat fungsi A memanggil fungsi B, Komputer menyimpan posisi fungsi A di stack agar bisa kembali lagi setelah funsgi B selesai.

# Operasi dasar pada stack
- `Push`: Menambahkan data ke tumpukan paling atas.
- `Pop`: Mengambil/menghapus data dari tumpukan paling atas.
- `Peek/Top`: Melihat data yang ada di paling atas tanpa menghapusnya
- `isEmpty`: Mengecek apakah tumpukan kosong.

### Stack di bahasa C melihat alamat memori
