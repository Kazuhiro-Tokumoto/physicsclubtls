// main.c
// emcc でコンパイルして Wasm にする
// JSから呼べるエクスポート関数群

#include <emscripten.h>
#include <string.h>
#include "field256.h"
#include "jacobian.h"

// =============================================
// 初期化（Gテーブル構築）
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_init(void) {
  init_g_table();
}

// =============================================
// スカラー倍: R = k * G
// 入力:  k_ptr  → 32バイト (ビッグエンディアン)
// 出力:  out_ptr → 64バイト (x: 32B + y: 32B, ビッグエンディアン)
// =============================================

// ビッグエンディアン32バイト → fe256 (リトルエンディアンlimb)
// bytes[0] = 最上位バイト → limb[3]の上位
// bytes[31] = 最下位バイト → limb[0]の下位
static void bytes_to_fe256(fe256 *r, const uint8_t *bytes) {
  // limb[3] = bytes[0..7], limb[2] = bytes[8..15],
  // limb[1] = bytes[16..23], limb[0] = bytes[24..31]
  for (int limb = 0; limb < 4; limb++) {
    const uint8_t *p = bytes + (3 - limb) * 8; // limb[3]→bytes[0], limb[0]→bytes[24]
    r->v[limb] = ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
                 ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
                 ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
                 ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
  }
}

// fe256 → ビッグエンディアン32バイト
static void fe256_to_bytes(uint8_t *bytes, const fe256 *a) {
  for (int limb = 0; limb < 4; limb++) {
    uint8_t *p = bytes + (3 - limb) * 8;
    uint64_t v = a->v[limb];
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
  }
}

EMSCRIPTEN_KEEPALIVE
void ec_dump_gtable(int i, int j, uint8_t *out_ptr) {
  // out_ptr: 96バイト (X:32 + Y:32 + Z:32)
  fe256_to_bytes(out_ptr,      &G_TABLE[i][j].X);
  fe256_to_bytes(out_ptr + 32, &G_TABLE[i][j].Y);
  fe256_to_bytes(out_ptr + 64, &G_TABLE[i][j].Z);
}

void ec_field_inv(const uint8_t *a_ptr, uint8_t *out_ptr) {
  fe256 a, r;
  bytes_to_fe256(&a, a_ptr);
  fe256_inv(&r, &a);
  fe256_to_bytes(out_ptr, &r);
}
void ec_scalar_mult_g(const uint8_t *k_ptr, uint8_t *out_ptr) {
  fe256 k;
  bytes_to_fe256(&k, k_ptr);

  aff_point R;
  scalar_mult_g(&R, &k);

  fe256_to_bytes(out_ptr, &R.x);
  fe256_to_bytes(out_ptr + 32, &R.y);
}

// =============================================
// 汎用スカラー倍: R = k * P
// 入力:  k_ptr → 32B, px_ptr → 32B, py_ptr → 32B (全部ビッグエンディアン)
// 出力:  out_ptr → 64B (x + y)
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_scalar_mult(const uint8_t *k_ptr, const uint8_t *px_ptr, const uint8_t *py_ptr, uint8_t *out_ptr) {
  fe256 k;
  aff_point P;
  bytes_to_fe256(&k, k_ptr);
  bytes_to_fe256(&P.x, px_ptr);
  bytes_to_fe256(&P.y, py_ptr);

  aff_point R;
  scalar_mult(&R, &k, &P);

  fe256_to_bytes(out_ptr, &R.x);
  fe256_to_bytes(out_ptr + 32, &R.y);
}

// =============================================
// Shamir's trick: R = k1*P1 + k2*P2
// 検証用
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_shamirs_mult(
  const uint8_t *k1_ptr, const uint8_t *p1x_ptr, const uint8_t *p1y_ptr,
  const uint8_t *k2_ptr, const uint8_t *p2x_ptr, const uint8_t *p2y_ptr,
  uint8_t *out_ptr
) {
  fe256 k1, k2;
  aff_point P1, P2;
  bytes_to_fe256(&k1, k1_ptr);
  bytes_to_fe256(&P1.x, p1x_ptr);
  bytes_to_fe256(&P1.y, p1y_ptr);
  bytes_to_fe256(&k2, k2_ptr);
  bytes_to_fe256(&P2.x, p2x_ptr);
  bytes_to_fe256(&P2.y, p2y_ptr);

  aff_point R;
  shamirs_mult(&R, &k1, &P1, &k2, &P2);

  fe256_to_bytes(out_ptr, &R.x);
  fe256_to_bytes(out_ptr + 32, &R.y);
}

// =============================================
// フィールド乗算テスト: r = (a * b) mod P
// 数値検証用
// =============================================
EMSCRIPTEN_KEEPALIVE
void ec_field_mul(const uint8_t *a_ptr, const uint8_t *b_ptr, uint8_t *out_ptr) {
  fe256 a, b, r;
  bytes_to_fe256(&a, a_ptr);
  bytes_to_fe256(&b, b_ptr);
  fe256_mul(&r, &a, &b);
  fe256_to_bytes(out_ptr, &r);
}

// デバッグ用: reduce前の512bit積を返す
EMSCRIPTEN_KEEPALIVE
void ec_field_mul_raw(const uint8_t *a_ptr, const uint8_t *b_ptr, uint8_t *out_ptr) {
  fe256 a, b;
  fe512 t;
  bytes_to_fe256(&a, a_ptr);
  bytes_to_fe256(&b, b_ptr);
  fe256_mul_raw(&t, &a, &b);
  for (int limb = 0; limb < 8; limb++) {
    uint8_t *p = out_ptr + (7 - limb) * 8;
    uint64_t v = t.v[limb];
    for (int j = 0; j < 8; j++) {
      p[j] = (uint8_t)(v >> (56 - j * 8));
    }
  }
}
EMSCRIPTEN_KEEPALIVE
void ec_dump_jac_double_g(uint8_t *out_ptr) {
  jac_point P;
  P.X = CURVE_G.x;
  P.Y = CURVE_G.y;
  P.Z = FIELD_ONE;
  jac_point R;
  jac_double(&R, &P);
  fe256_to_bytes(out_ptr,      &R.X);
  fe256_to_bytes(out_ptr + 32, &R.Y);
  fe256_to_bytes(out_ptr + 64, &R.Z);
}