// ============================================================================
// AVX512 SSr CROLL adaptation
// ComputeRoll (CROLL) PoW solver, AVX512 8-way, SSr-adapted.
// Satu file saja: kode + cara build + ringkasan hasil tes ada di file ini.
//
// APA INI
//   Solver untuk ComputeRoll di BNB Chain. Mencari nonce sehingga
//   keccak256(challenge 32 byte || wallet 20 byte || nonce 32 byte BE)
//   < target (input 84 byte, satu blok). Satu nonce yang lolos = 10.000 CROLL
//   (klaim on-chain tetap lewat preview + konfirmasi pemilik, solver ini
//   TIDAK pernah transaksi, TIDAK pernah signing, TIDAK ada jaringan).
//   Ini ADAPTASI SSr ke CROLL, BUKAN miner baton PodMint (rumus hash PodMint
//   beda: prefix ASCII + nonce desimal) dan BUKAN miner HashOre.
//
// CARA BUILD (Linux x86-64, CPU harus punya AVX512F + AVX512BW)
//   gcc -O3 -mavx512f -mavx512bw -pthread -Wall -Wextra -o AVX512_SSr_CROLL_adaptation AVX512_SSr_CROLL_adaptation.c
//   Cek CPU dulu: grep -o -m1 'avx512bw' /proc/cpuinfo
//   (harus keluar 'avx512bw', kalau tidak ada jangan dijalankan)
//
// CARA PAKAI
//   ./AVX512_SSr_CROLL_adaptation <challenge_hex> <miner_hex> <target_hex> [threads] [start_nonce] [end_nonce]
//   end_nonce 0 = tanpa batas. Kalau range selesai tanpa temuan, keluar
//   {"status":"range_done",...}.
//   Mode cek (verifikasi rumus hash, tanpa mining):
//   ./AVX512_SSr_CROLL_adaptation <challenge> <miner> <target> check <nonce>
//   Contoh nonce 0 untuk challenge/miner/target hi5 (30 Okt 2026):
//   hash harus 0x543fff867c34688a8a9d340ad638e772d092f2a0f07ac486b015f37c23c36ea4,
//   below_target 0.
//
// CHECKPOINT + RESUME
//   Tiap 5 detik solver menulis checkpoint atomik (tmp + rename) ke:
//     ./croll_ssr.checkpoint (direktori saat ini — diubah dari path absolut
//     workspace penulis agar bisa jalan di mesin siapa pun)
//   Isi: {"start","end","checkpoint_nonce","total_hashes_logged","elapsed_sec"}.
//   checkpoint_nonce = titik kontinu yang SUDAH dicari semua thread
//   (thread paling lambat), kelipatan 16, tanpa celah. Untuk resume, jalankan
//   lagi dengan start_nonce = checkpoint_nonce (solver TIDAK membaca file
//   ini otomatis). Overlap yang dicari ulang kalau resume: ~3 juta hash
//   (diukur, 0,60% dari total pada tes 946 detik) — kecil dan aman.
//
// HASIL TES (30 Okt 2026, VM 2 core AMD EPYC, dibandingkan langsung)
//   Kebenaran: mode check + uji temuan (target maks) cocok persis dengan
//     keccak Python independen; kandidat temuan dicek ulang jalur skalar
//     sebelum JSON dicetak (gagal = exit error, tanpa JSON).
//   Kecepatan (range aman yang sama, 2 thread, sambil solver live jalan):
//     scalar ~1,00 M/s | AVX2 ~2,93 M/s | AVX512 live ~5,99 M/s |
//     adaptasi ini ~5,91 M/s — seri dengan AVX512 live, ~2,1x AVX2, ~6x scalar.
//   Tes 30 menit (berhenti dini di 946 detik karena kill runtime):
//     total 5.167,8 juta hash, rata-rata bertahan 5,463 M/s, maks 5,47 M/s,
//     rata-rata progres 5,362 M/s, simpangan 0,123, tanpa penurunan.
//   Ketahanan: checkpoint selamat utuh setelah kill; solver TIDAK auto-restart
//     (tidak ada watchdog untuk file ini) — solver live AVX512 yang punya
//     watchdog bangkit otomatis dari log.
//   Maksimal: gabungan dua solver di VM ini = 11,19 M/s (plafon 2 core);
//     rekor solver live sendirian = 11,11 M/s. Tidak ada solver yang melewati
//     ~11 M/s di VM ini.
//   Kesimpulan tes: adaptasi ini akurat, konsisten, resume-nya paling rapi,
//     tapi kecepatannya seri dengan AVX512 live — bukan pengganti yang lebih
//     cepat, melainkan alternatif yang lebih aman soal resume.
//   CATATAN PENTING: versi kiriman awal punya path checkpoint absolut
//     workspace penulis yang tidak ada di mesin lain. Di paket repo ini
//     path-nya diubah ke ./croll_ssr.checkpoint (direktori saat ini)
//     agar bisa jalan di mesin siapa pun.
//
// KEAMANAN
//   Komputasi lokal saja. Tidak ada socket/jaringan, tidak ada wallet,
//   tidak ada signing, tidak ada pengiriman data. Satu-satunya file yang
//   ditulis adalah checkpoint di atas (+ .tmp saat penulisan).
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <immintrin.h>

static const uint64_t RC[24] = {
  0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
  0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
  0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
  0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL
};
static const int R[5][5] = {
  {0,36,3,41,18},{1,44,10,45,2},{62,6,43,15,61},{28,55,25,21,56},{27,20,39,8,14}
};
static __m512i ROTV[25];
static __m512i ROT1V;
static void init_rotvecs(void) {
  // ROTV[x+5*y] = R[x][y] from the CROLL R table, same order as SSr.
  for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
    ROTV[x + 5*y] = _mm512_set1_epi64((long long)R[x][y]);
  ROT1V = _mm512_set1_epi64(1);
}
static inline __m512i rolv(__m512i v, __m512i rvec) {
  return _mm512_rolv_epi64(v, rvec);
}
static void keccak_f1600_avx512(__m512i st[25]) {
  for (int round = 0; round < 24; round++) {
    __m512i C[5], D[5], B[25];
    for (int x = 0; x < 5; x++)
      C[x] = _mm512_xor_epi64(_mm512_xor_epi64(_mm512_xor_epi64(_mm512_xor_epi64(
                st[x], st[x + 5]), st[x + 10]), st[x + 15]), st[x + 20]);
    for (int x = 0; x < 5; x++)
      D[x] = _mm512_xor_epi64(C[(x + 4) % 5], rolv(C[(x + 1) % 5], ROT1V));
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
      st[x + 5 * y] = _mm512_xor_epi64(st[x + 5 * y], D[x]);
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
      B[y + 5 * ((2 * x + 3 * y) % 5)] = rolv(st[x + 5 * y], ROTV[x + 5 * y]);
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
      st[x + 5 * y] = _mm512_xor_epi64(B[x + 5 * y],
        _mm512_andnot_epi64(B[((x + 1) % 5) + 5 * y], B[((x + 2) % 5) + 5 * y]));
    st[0] = _mm512_xor_epi64(st[0], _mm512_set1_epi64((long long)RC[round]));
  }
}
static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static int parse_hex(const char *s, uint8_t *out, size_t nbytes) {
  if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
  if (strlen(s) != nbytes * 2) return -1;
  for (size_t i = 0; i < nbytes; i++) {
    int hi = hexval((unsigned char)s[2*i]), lo = hexval((unsigned char)s[2*i+1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}
static uint8_t CHALLENGE[32], MINER[20], TARGET[32];
static int NTHREADS;
static uint64_t START;
static uint64_t END_N;
static _Atomic int FOUND = 0;
static _Atomic uint64_t FOUND_NONCE = 0;
static _Atomic uint64_t *TRIED;
static _Atomic int DONE_THREADS = 0;
// Lane values of the 84-byte block that are constant across nonces.
static uint64_t CONST_LANE[25];
static void build_const_lanes(void) {
  // Lanes 0..5: challenge bytes 0..47 (LE per 8-byte lane), lane 6 low half = miner tail.
  uint8_t msg[52];
  memcpy(msg, CHALLENGE, 32);
  memcpy(msg + 32, MINER, 20);
  for (int i = 0; i < 7; i++) {
    uint64_t v = 0;
    for (int j = 0; j < 8; j++) {
      int idx = i*8 + j;
      uint8_t b = idx < 52 ? msg[idx] : 0;
      v |= (uint64_t)b << (8*j);
    }
    CONST_LANE[i] = v;
  }
  for (int i = 7; i < 25; i++) CONST_LANE[i] = 0;
  CONST_LANE[16] = 0x8000000000000000ULL; // padding: message byte 135 ^= 0x80
}
static inline uint64_t lane9_of(uint64_t nonce) {
  uint64_t nb0 = (nonce >> 56) & 0xFF, nb1 = (nonce >> 48) & 0xFF;
  uint64_t nb2 = (nonce >> 40) & 0xFF, nb3 = (nonce >> 32) & 0xFF;
  return (nb0 << 32) | (nb1 << 40) | (nb2 << 48) | (nb3 << 56);
}
static inline uint64_t lane10_of(uint64_t nonce) {
  uint64_t nb4 = (nonce >> 24) & 0xFF, nb5 = (nonce >> 16) & 0xFF;
  uint64_t nb6 = (nonce >> 8) & 0xFF, nb7 = nonce & 0xFF;
  return nb4 | (nb5 << 8) | (nb6 << 16) | (nb7 << 24) | (0x01ULL << 32); // padding byte 84
}
// Runs one batch of 8 nonces (base..base+7). Returns the winning lane 0..7, or -1.
static int run_batch(uint64_t base, uint8_t hashes[8][32]) {
  __m512i st[25];
  for (int i = 0; i < 25; i++) st[i] = _mm512_set1_epi64((long long)CONST_LANE[i]);
  st[9] = _mm512_set_epi64((long long)lane9_of(base+7), (long long)lane9_of(base+6),
    (long long)lane9_of(base+5), (long long)lane9_of(base+4), (long long)lane9_of(base+3),
    (long long)lane9_of(base+2), (long long)lane9_of(base+1), (long long)lane9_of(base));
  st[10] = _mm512_set_epi64((long long)lane10_of(base+7), (long long)lane10_of(base+6),
    (long long)lane10_of(base+5), (long long)lane10_of(base+4), (long long)lane10_of(base+3),
    (long long)lane10_of(base+2), (long long)lane10_of(base+1), (long long)lane10_of(base));
  keccak_f1600_avx512(st);
  // Squeeze lanes 0..3: hash bytes 0..31, lane i (LE) = bytes 8i..8i+7.
  uint64_t lanes[4][8];
  for (int i = 0; i < 4; i++) _mm512_storeu_si512((__m512i *)lanes[i], st[i]);
  for (int j = 0; j < 8; j++) {
    uint8_t h[32];
    for (int k = 0; k < 32; k++) h[k] = (uint8_t)(lanes[k/8][j] >> (8*(k%8)));
    memcpy(hashes[j], h, 32);
  }
  for (int j = 0; j < 8; j++) {
    if (END_N != 0 && base + (uint64_t)j >= END_N) continue;
    int below = 0, decided = 0;
    for (int k = 0; k < 32; k++) {
      if (hashes[j][k] != TARGET[k]) { below = hashes[j][k] < TARGET[k]; decided = 1; break; }
    }
    if (!decided) below = 0; // equal is not below
    if (below) return j;
  }
  return -1;
}
static void *worker(void *arg) {
  long tid = (long)arg;
  uint64_t base = START + (uint64_t)tid*8;
  uint64_t step = (uint64_t)NTHREADS*8;
  uint64_t tried = 0;
  uint8_t hashes[8][32];
  while (!atomic_load(&FOUND)) {
    if (END_N != 0 && base >= END_N) break;
    int win = run_batch(base, hashes);
    tried += 8;
    if ((tried & 0xFFF) == 0) atomic_store(&TRIED[tid], tried);
    if (win >= 0) {
      int expected = 0;
      if (atomic_compare_exchange_strong(&FOUND, &expected, 1))
        atomic_store(&FOUND_NONCE, base + (uint64_t)win);
      break;
    }
    base += step;
  }
  atomic_store(&TRIED[tid], tried);
  atomic_fetch_add(&DONE_THREADS, 1);
  return NULL;
}

#define ROTL_SCALAR(x,n) (((x)<<(n))|((x)>>(64-(n))))
static void keccak_f1600_scalar(uint64_t st[25]) {
  for (int round = 0; round < 24; round++) {
    uint64_t C[5], D[5];
    for (int x = 0; x < 5; x++) C[x] = st[x]^st[x+5]^st[x+10]^st[x+15]^st[x+20];
    for (int x = 0; x < 5; x++) D[x] = C[(x+4)%5]^ROTL_SCALAR(C[(x+1)%5],1);
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) st[x+5*y] ^= D[x];
    uint64_t B[25];
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++) {
      int nx = y, ny = (2*x+3*y)%5;
      B[nx+5*ny] = ROTL_SCALAR(st[x+5*y], R[x][y]);
    }
    for (int x = 0; x < 5; x++) for (int y = 0; y < 5; y++)
      st[x+5*y] = B[x+5*y] ^ ((~B[((x+1)%5)+5*y]) & B[((x+2)%5)+5*y]);
    st[0] ^= RC[round];
  }
}
static void scalar_hash_of(uint64_t nonce, uint8_t out[32]) {
  uint8_t buf[84];
  memcpy(buf, CHALLENGE, 32);
  memcpy(buf + 32, MINER, 20);
  memset(buf + 52, 0, 32);
  for (int i = 0; i < 8; i++) buf[52 + 24 + i] = (uint8_t)(nonce >> (8 * (7 - i)));
  uint64_t st[25];
  memset(st, 0, sizeof st);
  uint8_t block[136];
  memset(block, 0, sizeof block);
  memcpy(block, buf, 84);
  block[84] ^= 0x01;
  block[135] ^= 0x80;
  for (int i = 0; i < 17; i++) {
    uint64_t v = 0;
    for (int j = 0; j < 8; j++) v |= (uint64_t)block[i*8 + j] << (8*j);
    st[i] ^= v;
  }
  keccak_f1600_scalar(st);
  for (int i = 0; i < 4; i++) {
    uint64_t v = st[i];
    for (int j = 0; j < 8; j++) out[i*8 + j] = (uint8_t)(v >> (8*j));
  }
}
static int scalar_below_target(const uint8_t *h) {
  for (int i = 0; i < 32; i++) if (h[i] != TARGET[i]) return h[i] < TARGET[i];
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: AVX512_SSr_CROLL_adaptation <challenge> <miner> <target> [threads] [start_nonce] [end_nonce]\n"
                    "       AVX512_SSr_CROLL_adaptation <challenge> <miner> <target> check <nonce>\n");
    return 2;
  }
  if (parse_hex(argv[1], CHALLENGE, 32) != 0 ||
      parse_hex(argv[2], MINER, 20) != 0 ||
      parse_hex(argv[3], TARGET, 32) != 0) {
    fprintf(stderr, "bad hex input (need 32B challenge, 20B miner, 32B target)\n");
    return 2;
  }
  build_const_lanes();
  init_rotvecs();
  if (!__builtin_cpu_supports("avx512f") || !__builtin_cpu_supports("avx512bw")) {
    fprintf(stderr, "error: CPU does not support AVX512F+BW\n");
    return 2;
  }
  if (argc >= 5 && strcmp(argv[4], "check") == 0) {
    if (argc < 6) { fprintf(stderr, "check needs a nonce\n"); return 2; }
    uint64_t nonce = strtoull(argv[5], NULL, 10);
    uint8_t hashes[8][32];
    run_batch(nonce, hashes);
    printf("hash: 0x");
    for (int i = 0; i < 32; i++) printf("%02x", hashes[0][i]);
    int below = 0;
    for (int k = 0; k < 32; k++) {
      if (hashes[0][k] != TARGET[k]) { below = hashes[0][k] < TARGET[k]; break; }
    }
    printf("\nbelow_target: %d\n", below);
    return 0;
  }
  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  NTHREADS = argc >= 5 ? atoi(argv[4]) : (int)cpus;
  if (NTHREADS < 1) NTHREADS = 1;
  if (NTHREADS > 64) NTHREADS = 64;
  START = argc >= 6 ? strtoull(argv[5], NULL, 10) : 0;
  END_N = argc >= 7 ? strtoull(argv[6], NULL, 10) : 0;
  TRIED = calloc((size_t)NTHREADS, sizeof(_Atomic uint64_t));
  pthread_t *th = malloc(sizeof(pthread_t) * (size_t)NTHREADS);
  struct timespec t0, now;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (long t = 0; t < NTHREADS; t++) pthread_create(&th[t], NULL, worker, (void *)t);
  while (!atomic_load(&FOUND) && atomic_load(&DONE_THREADS) < NTHREADS) {
    struct timespec ts = {5, 0};
    nanosleep(&ts, NULL);
    clock_gettime(CLOCK_MONOTONIC, &now);
    double el = (now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9;
    uint64_t tot = 0;
    uint64_t min_tried = UINT64_MAX;
    for (int t = 0; t < NTHREADS; t++) {
      uint64_t tv = atomic_load(&TRIED[t]);
      tot += tv;
      if (tv < min_tried) min_tried = tv;
    }
    fprintf(stderr, "[AVX512_SSr_CROLL_adaptation] %.1fM hashes, %.2fM/s, %d threads, %.0fs, start %llu\n",
      tot / 1e6, el > 0 ? tot / el / 1e6 : 0, NTHREADS, el,
      (unsigned long long)START);
    // Checkpoint yang dijamin tanpa celah: titik kontinu = START +
    // (batch paling sedikit yang sudah diselesaikan SEMUA thread) * NTHREADS * 8.
    // Thread yang lebih maju akan diulang sedikit saat resume, itu aman.
    // File ditulis atomik (tmp + rename) di direktori saat ini, jadi tahan restart.
    if (min_tried != UINT64_MAX) {
      uint64_t min_batches = min_tried / 8;
      uint64_t contiguous = START + min_batches * (uint64_t)NTHREADS * 8;
      if (END_N != 0 && contiguous > END_N) contiguous = END_N;
      FILE *cf = fopen("croll_ssr.checkpoint.tmp", "w");
      if (cf) {
        fprintf(cf, "{\"start\":\"%llu\",\"end\":\"%llu\",\"checkpoint_nonce\":\"%llu\",\"total_hashes_logged\":\"%llu\",\"elapsed_sec\":\"%.0f\"}\n",
          (unsigned long long)START, (unsigned long long)END_N,
          (unsigned long long)contiguous, (unsigned long long)tot, el);
        fclose(cf);
        rename("croll_ssr.checkpoint.tmp",
               "croll_ssr.checkpoint");
      }
      fprintf(stderr, "[checkpoint] lanjutkan dari %llu\n", (unsigned long long)contiguous);
    }
  }
  for (int t = 0; t < NTHREADS; t++) pthread_join(th[t], NULL);
  if (!atomic_load(&FOUND)) {
    printf("{\"status\":\"range_done\",\"start\":\"%llu\",\"end\":\"%llu\"}\n",
      (unsigned long long)START, (unsigned long long)END_N);
    return 0;
  }
  uint64_t fn = atomic_load(&FOUND_NONCE);
  uint8_t hashes[8][32];
  run_batch(fn, hashes);
  uint8_t shash[32];
  scalar_hash_of(fn, shash);
  if (memcmp(shash, hashes[0], 32) != 0 || !scalar_below_target(shash)) {
    fprintf(stderr, "ERROR: scalar recheck failed for nonce %llu, no JSON printed\n", (unsigned long long)fn);
    return 3;
  }
  printf("{\"nonce\":\"%llu\",\"hash\":\"0x", (unsigned long long)fn);
  for (int i = 0; i < 32; i++) printf("%02x", hashes[0][i]);
  printf("\",\"below_target\":1}\n");
  return 0;
}
