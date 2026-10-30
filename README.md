# AVX512-ssr Miner CROLL Adaptation

Ini adalah adaptasi AVX512 untuk mining CROLL di BSC.

Created by Cervus. If you use this, please keep crediting the creator.
Copyright (c) 2026 Cervus.

## Apa ini

Solver ComputeRoll (CROLL) Proof-of-Work di BNB Chain, AVX512 8-way.
Mencari nonce sehingga:

```
keccak256(challenge 32 byte || wallet/miner 20 byte || nonce 32 byte big-endian) < target
```

Input 84 byte, satu blok Keccak. Satu nonce yang lolos = 10.000 CROLL
(sesuai dokumen solver; klaim on-chain tetap langkah terpisah oleh pemilik).

Solver ini murni komputasi lokal: tidak ada jaringan, tidak ada signing,
tidak ada transaksi. Temuan dicek ulang lewat jalur skalar sebelum JSON
dicetak — kalau recheck gagal, tidak ada JSON yang keluar (exit error).

## Isi repo

- `AVX512_SSr_CROLL_adaptation.c` — solver AVX512 (satu file).
- `verify.py` — verifikasi rumus hash lawan keccak Python.
- `LICENSE` — MIT.

## Build

Syarat: Linux x86-64, CPU harus punya AVX512F + AVX512BW. Cek dulu:

```bash
grep -o -m1 'avx512bw' /proc/cpuinfo   # harus keluar 'avx512bw', kalau tidak ada jangan dijalankan
```

Perintah:

```bash
gcc -O3 -mavx512f -mavx512bw -pthread -Wall -Wextra -o AVX512_SSr_CROLL_adaptation AVX512_SSr_CROLL_adaptation.c
```

## Cara pakai

```bash
./AVX512_SSr_CROLL_adaptation <challenge_hex> <miner_hex> <target_hex> [threads] [start_nonce] [end_nonce]
```

`end_nonce` 0 = tanpa batas. Kalau range selesai tanpa temuan, keluar
`{"status":"range_done",...}`. Pakai challenge, miner, dan target milik
sendiri dari chain — jangan memakai nilai orang lain.

Mode cek (verifikasi rumus hash, tanpa mining):

```bash
./AVX512_SSr_CROLL_adaptation <challenge> <miner> <target> check <nonce>
```

Keluarannya `hash: 0x...` dan `below_target: 0/1`. Bandingkan dengan
`verify.py` untuk memastikan rumus yang dipakai solver sama dengan
keccak Python:

```bash
python3 verify.py <challenge_hex> <miner_hex> <target_hex> <nonce>
# butuh pycryptodome: pip install pycryptodome
```

## Checkpoint + resume

Tiap 5 detik solver menulis checkpoint atomik (tmp + rename) ke
`./croll_ssr.checkpoint` di direktori saat ini. Isinya:
`start`, `end`, `checkpoint_nonce`, `total_hashes_logged`, `elapsed_sec`.
`checkpoint_nonce` = titik kontinu yang sudah dicari semua thread
(thread paling lambat), tanpa celah.

Untuk resume, jalankan lagi dengan `start_nonce = checkpoint_nonce`.
Solver TIDAK membaca file checkpoint otomatis, dan tidak ada watchdog /
auto-restart — resume dilakukan manual.

## Hasil tes (dari dokumen solver)

VM 2 core, perbandingan langsung: skalar ~1,00 M/s, AVX2 ~2,93 M/s,
AVX512 live ~5,99 M/s, adaptasi ini ~5,91 M/s — seri dengan AVX512 live,
~2,1x AVX2, ~6x skalar (diukur saat solver live jalan bareng).
Tes 30 menit: 5.167,8 juta hash, rata-rata bertahan 5,463 M/s, tanpa
penurunan; checkpoint selamat utuh setelah kill.

Verifikasi lokal paket ini: compile bersih nol warning; mode cek cocok
persis dengan keccak Python; checkpoint tertulis di direktori saat ini.

## Lisensi

MIT (lihat `LICENSE`).

## Penafian

Proyek independen. Gunakan dengan risiko sendiri. Verifikasi temuan
secara independen sebelum klaim on-chain apa pun. Jangan pernah memakai
nonce yang belum terverifikasi.
