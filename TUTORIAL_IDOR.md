
# Tutorial: Menggunakan Fitur Uji Coba IDOR di NetiV3

Dokumen ini menjelaskan cara menggunakan fitur pengujian kerentanan IDOR (Insecure Direct Object References) yang ada di dalam aplikasi NetiV3.

**PERINGATAN:** Fitur ini ditujukan untuk tujuan edukasi dan pengujian keamanan pada aplikasi yang Anda miliki atau yang telah memberikan izin eksplisit kepada Anda. Menggunakan fitur ini pada sistem tanpa izin adalah tindakan ilegal dan tidak etis.

---

## Konsep Dasar IDOR

IDOR adalah kerentanan di mana seorang pengguna dapat mengakses data atau objek milik pengguna lain hanya dengan mengubah nilai parameter ID di URL atau permintaan lainnya. Contoh: mengubah `?user_id=100` menjadi `?user_id=101` untuk melihat data pengguna lain.

Fitur ini membantu Anda mengotomatiskan proses tersebut untuk menemukan potensi kerentanan.

---

## Tahap 1: Persiapan (di Aplikasi Target)

Sebelum menggunakan NetiV3, Anda perlu mengumpulkan beberapa informasi dari aplikasi web yang ingin Anda uji.

Anda memerlukan akses ke dua akun pengguna:
- **Pengguna A:** Akun Anda, yang akan digunakan untuk melancarkan pengujian.
- **Pengguna B:** Akun lain yang akan menjadi target/korban.

### 1. Dapatkan Cookie Sesi Pengguna A
Cookie adalah identitas login Anda di sebuah situs.

- Login ke aplikasi target sebagai **Pengguna A**.
- Buka **Developer Tools** di browser Anda (tekan F12).
- Buka tab **Application** (di Chrome/Edge) atau **Storage** (di Firefox).
- Di menu sebelah kiri, cari bagian **Cookies** dan klik pada domain aplikasi target.
- Salin **seluruh nilai cookie** yang terkait dengan sesi login Anda. Nilainya bisa terlihat seperti `session=a1b2c3d4e5f6; theme=dark; tracking_id=xyz`.

### 2. Identifikasi URL Target dan ID
- Saat masih login sebagai Pengguna A, buka halaman yang menampilkan data spesifik milik Anda (contoh: halaman profil, pesanan, atau dokumen).
- Lihat URL di address bar browser Anda. Cari pola yang menggunakan ID unik.
  - Contoh: `https://aplikasitarget.com/profile.php?user_id=123`
- Catat URL ini dan ID milik Pengguna A (dalam contoh ini, `123`).

### 3. Dapatkan ID Pengguna B
- Cari tahu ID milik **Pengguna B**. Tergantung pada aplikasi, ID ini mungkin terlihat di profil publik pengguna lain atau di tempat lain.
  - Contoh: ID Pengguna B adalah `456`.

---

## Tahap 2: Eksekusi (di NetiV3)

Buka aplikasi NetiV3 Anda dan navigasikan ke halaman **`/idor_run`**. Anda akan melihat sebuah form. Isi form tersebut dengan informasi yang sudah Anda kumpulkan.

### Contoh Pengisian Form:

- **URL Target dengan Placeholder:**
  Ganti ID spesifik di URL yang Anda catat dengan placeholder `__ID__`.
  - *Isi dengan:* `https://aplikasitarget.com/profile.php?user_id=__ID__`

- **Daftar ID untuk Diuji:**
  Masukkan ID-ID yang ingin Anda coba akses (termasuk ID Pengguna B), dipisahkan dengan koma.
  - *Isi dengan:* `456, 457, 100`

- **Cookie Sesi Pengguna A:**
  Tempel (paste) seluruh nilai cookie yang Anda salin dari browser untuk Pengguna A.
  - *Isi dengan:* `session=a1b2c3d4e5f6; theme=dark; tracking_id=xyz`

- **ID Milik Pengguna A:**
  Masukkan ID asli milik Pengguna A. Ini akan digunakan sebagai pembanding (baseline).
  - *Isi dengan:* `123`

Setelah semua terisi, klik tombol **"Mulai Uji Coba"**.

---

## Tahap 3: Analisis Hasil

Hasil pengujian akan ditampilkan di kotak output dalam format JSON. Perhatikan nilai dari `"status"` untuk setiap ID yang diuji.

- **`"status": "Baseline"`**
  Ini adalah hasil permintaan ke ID Anda sendiri (`123`). Hasil ini digunakan sebagai acuan "sukses yang diharapkan". Seharusnya menunjukkan `http_code: 200`.

- **`"status": "VULNERABLE"`**
  **Ini berarti kerentanan IDOR ditemukan!** NetiV3 berhasil mengakses data milik ID lain menggunakan sesi Anda dan mendapatkan respons sukses (`http_code: 200`), sama seperti saat mengakses data Anda sendiri.

- **`"status": "Secure"`**
  Ini berarti aplikasi target aman dari percobaan ini. Server merespons dengan benar dengan menolak akses, yang ditandai dengan `http_code` seperti `403 Forbidden`, `401 Unauthorized`, atau `404 Not Found`.

- **`"status": "Error"`**
  Terjadi kesalahan saat mencoba menghubungi URL target, misalnya karena koneksi gagal atau timeout.

Dengan mengikuti panduan ini, Anda dapat secara sistematis dan efektif menggunakan fitur pengujian IDOR di NetiV3.
