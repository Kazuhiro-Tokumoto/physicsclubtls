import { getRandomValues } from "crypto";
import { get } from "http";

function xorEncrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    key = hkdf(key, iv, new Uint8Array(0), 32);
    const cryptokey = hkdf(
        key,
        iv,
        new TextEncoder().encode("encryption"),
        32,
    )
    const encrypted = data.map((byte, i) => byte ^ cryptokey[i % cryptokey.length]);
    const macKey = hkdf(
      key,
      iv,
      new TextEncoder().encode("mac"),
      32,
    );
    const mac = hmacSha256(macKey, concat(iv, encrypted));
    return new Uint8Array([...iv, ...encrypted, ...mac]);
}
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

function xorDecrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
    const iv = data.slice(0, 16);
    const mac = data.slice(-32);
    key = hkdf(key, iv, new Uint8Array(0), 32);
    const cryptokey = hkdf(
        key,
        iv,
        new TextEncoder().encode("encryption"),
        32
    );
    const decrypted = data.slice(16, -32).map((byte, i) => byte ^ cryptokey[i % cryptokey.length]);
    const macKey = hkdf(
      key,
      iv,
      new TextEncoder().encode("mac"),
      32,
    );
    const expectedMac = hmacSha256(macKey, concat(iv, data.slice(16, -32)));
    if (!timingSafeEqual(expectedMac, mac)) {
        throw new Error("MAC verification failed");
    }
    return decrypted;
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return sha256(concat(opad, sha256(concat(ipad, data))));
  }

function concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }
function sha256(data: Uint8Array): Uint8Array {
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

    let h0 = 0x6a09e667,
      h1 = 0xbb67ae85,
      h2 = 0x3c6ef372,
      h3 = 0xa54ff53a;
    let h4 = 0x510e527f,
      h5 = 0x9b05688c,
      h6 = 0x1f83d9ab,
      h7 = 0x5be0cd19;

    const len = data.length;
    const bitLen = len * 8;
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    view.setUint32(blocks.length - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(blocks.length - 4, bitLen >>> 0, false);

    for (let i = 0; i < blocks.length; i += 64) {
      const W = new Uint32Array(64);
      for (let t = 0; t < 16; t++) {
        W[t] = view.getUint32(i + t * 4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }

      let a = h0,
        b = h1,
        c = h2,
        d = h3;
      let e = h4,
        f = h5,
        g = h6,
        h = h7;

      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ ((~e >>> 0) & g); // ✅ ~e を明示的にuint32化
        const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;

        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
      h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0;
      h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);
    return result;
  }

function hkdf(
    inputKey: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): Uint8Array {
    const prk = hmacSha256(salt, inputKey);
    const out = new Uint8Array(length);
    let prev = new Uint8Array(0);
    let pos = 0;
    let counter = 1;
    while (pos < length) {
      prev = hmacSha256(
        prk,
        concat(prev, info, new Uint8Array([counter++])),
      ) as Uint8Array<ArrayBuffer>;
      const take = Math.min(prev.length, length - pos);
      out.set(prev.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const plain = encoder.encode("Hello, World!");
let key = encoder.encode("secret");

let decrypted: Uint8Array = new Uint8Array(0);
let encrypted: Uint8Array = new Uint8Array(0);
    encrypted = xorEncrypt(plain, key);
    decrypted = xorDecrypt(encrypted, key);
const times: number[] = [];
for (let i = 0; i < 1000; i++) xorDecrypt(encrypted, key);
for (let i = 0; i < 100000; i++) {
    const start = performance.now();
    key = getRandomValues(new Uint8Array(32));
    encrypted = xorEncrypt(plain, key);
    decrypted = xorDecrypt(encrypted, key);
    const end = performance.now();
    times.push(end - start);
}

times.sort((a, b) => a - b);

const sum = times.reduce((a, b) => a + b, 0);
const mean = sum / times.length;
const median = times[Math.floor(times.length / 2)];
const min = times[0];
const max = times[times.length - 1];
const p99 = times[Math.floor(times.length * 0.99)];

// 標準偏差
const variance = times.reduce((a, b) => a + (b - mean) ** 2, 0) / times.length;
const stddev = Math.sqrt(variance);

console.log(`件数:     ${times.length}`);
console.log(`平均:     ${mean.toFixed(4)}ms`);
console.log(`中央値:   ${median.toFixed(4)}ms`);
console.log(`最小値:   ${min.toFixed(4)}ms`);
console.log(`最大値:   ${max.toFixed(4)}ms`);
console.log(`P99:      ${p99.toFixed(4)}ms`);
console.log(`標準偏差: ${stddev.toFixed(4)}ms`);