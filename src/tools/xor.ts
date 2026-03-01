export class cipher {

  // =====================================================================
  // sha256 ばぐがおおそう
  // =====================================================================
  private sha256(data: Uint8Array): Uint8Array {
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
    // ★ここを正しく修正★
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    // ビット長（big-endian）
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
        W[t] = (((W[t - 16] + s0) | 0) + ((W[t - 7] + s1) | 0)) >>> 0;
      }
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 =
          (((h + S1) | 0) + (ch | 0) + (K[t] | 0) + (W[t] | 0)) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = ((S0 + maj) | 0) >>> 0;
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
    const resultView = new DataView(result.buffer);
    resultView.setUint32(0, h0, false);
    resultView.setUint32(4, h1, false);
    resultView.setUint32(8, h2, false);
    resultView.setUint32(12, h3, false);
    resultView.setUint32(16, h4, false);
    resultView.setUint32(20, h5, false);
    resultView.setUint32(24, h6, false);
    resultView.setUint32(28, h7, false);
    return result;
  }

  // ---------------------------------------------------------------------
  // ユーティリティ
  // ---------------------------------------------------------------------
  private bigintToHex(n: bigint, byteLength?: number): string {
    const hex = n.toString(16).toUpperCase();
    const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
    return hex.padStart(padLen, "0");
  }
  private BigintToBytes(n: bigint, byteLength?: number): Uint8Array {
    const hex = this.bigintToHex(n, byteLength);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  private hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }
  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);

    let i = 0;
    for (; i <= len - 8; i += 8) {
      res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
      res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
  }
  public bytesToHex(bytes: Uint8Array): string {
    return this.bigintToHex(this.bytesToBigInt(bytes));
  }
  public hexToBytes(hex: string): Uint8Array {
    return this.BigintToBytes(this.hexToBigInt(hex));
  }
  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  private counterToBytes(n: number): Uint8Array {
    const buf = new Uint8Array(4);
    new DataView(buf.buffer).setUint32(0, n, false);
    return buf;
  }

  // ---------------------------------------------------------------------
  // 1000回ストレッチング
  // ブルートフォース対策：10000回ハッシュして鍵を強化する
  // ---------------------------------------------------------------------
  private stretch(data: Uint8Array): Uint8Array {
    let h = data;
    for (let i = 0; i < 10000; i++) {
      h = this.sha256(h);
    }
    return h;
  }

  // ---------------------------------------------------------------------
  // HMAC-SHA256
  // ---------------------------------------------------------------------
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  // ---------------------------------------------------------------------
  // HKDF（暗号化用とMAC用で独立した鍵を導出）
  // ---------------------------------------------------------------------
  private hkdf(
    inputKey: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number
  ): Uint8Array {
    const prk = this.hmacSha256(salt, inputKey);
    const out = new Uint8Array(length);
    let prev = new Uint8Array(0);
    let pos = 0;
    let counter = 1;
    while (pos < length) {
      prev = this.hmacSha256(prk, this.concat(prev, info, new Uint8Array([counter++]))) as Uint8Array<ArrayBuffer>;
      const take = Math.min(prev.length, length - pos);
      out.set(prev.subarray(0, take), pos);
      pos += take;
    }
    return out;
  }

  // ---------------------------------------------------------------------
  // CTR モード（SHA-256 ベース）
  // ---------------------------------------------------------------------
private ctrProcess(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const BLOCK = 32;
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += BLOCK) {
    const counter = Math.floor(i / BLOCK);
    // sha256 の代わりに hmacSha256 を使う
    const blockKey = this.hmacSha256(key, this.concat(iv, this.counterToBytes(counter)));
    const end = Math.min(BLOCK, data.length - i);
    for (let j = 0; j < end; j++) {
      result[i + j] = data[i + j] ^ blockKey[j];
    }
  }
  return result;
}

  // ---------------------------------------------------------------------
  // 暗号化
  // 出力フォーマット: [ IV (16B) | 暗号文 | HMAC (32B) ]
  // ---------------------------------------------------------------------
  public encrypt = (rawData: Uint8Array, key: Uint8Array): Uint8Array => {
    // 鍵は32Bのみ受け付ける
    if (key.length !== 32) {
      throw new Error("鍵は32バイトにしてください");
    }

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));

    // 鍵を10000回ストレッチ
    const stretchedKey = this.stretch(key);

    // HKDF で暗号化用とMAC用を独立して導出
    const encKey = this.hkdf(stretchedKey, iv, new TextEncoder().encode("enc"), 32);
    const macKey = this.hkdf(stretchedKey, iv, new TextEncoder().encode("mac"), 32);

    const ciphertext = this.ctrProcess(rawData, encKey, iv);
    const mac = this.hmacSha256(macKey, this.concat(iv, ciphertext));

    return this.concat(iv, ciphertext, mac);
  };

  // ---------------------------------------------------------------------
  // 復号
  // 改ざんを検知した場合は null を返します
  // ---------------------------------------------------------------------
  public decrypt = (encryptedWithIv: Uint8Array, key: Uint8Array): Uint8Array | null => {
    // 鍵は32Bのみ受け付ける
    if (key.length !== 32) {
      throw new Error("鍵は32バイトにしてください");
    }

    // フォーマット: [ IV (16B) | 暗号文 | HMAC (32B) ]
    if (encryptedWithIv.length < 16 + 32) {
      console.error("decrypt error: データが短すぎます");
      return null;
    }

    const iv = encryptedWithIv.slice(0, 16);
    const mac = encryptedWithIv.slice(-32);
    const ciphertext = encryptedWithIv.slice(16, -32);

    // 鍵を10000回ストレッチ
    const stretchedKey = this.stretch(key);

    // HKDF で同じ鍵を再導出
    const encKey = this.hkdf(stretchedKey, iv, new TextEncoder().encode("enc"), 32);
    const macKey = this.hkdf(stretchedKey, iv, new TextEncoder().encode("mac"), 32);

    // MAC 検証（タイミング攻撃対策で全バイト比較）
    const expectedMac = this.hmacSha256(macKey, this.concat(iv, ciphertext));
    let diff = 0;
    for (let i = 0; i < 32; i++) {
      diff |= mac[i] ^ expectedMac[i];
    }
    if (diff !== 0) {
      console.error("decrypt error: MAC 検証失敗（改ざんの可能性）");
      return null;
    }

    return this.ctrProcess(ciphertext, encKey, iv);
  };
}
export class dsa{
  private readonly p: bigint = 0x863a7811a995cff52cc38ccd9ff9478f00768f7e265d7f9389d697c5fb45eae78b76063fe1f406b566d3a0dedcb17211213571497e506eb586fdaea2d9625f8aa254610674178211d4eaf173c2c3c7d66a56f4f93989dc8d37953978d41618e00eb95aa2e77b7e81a0c571158f4afdfcda01fecc085ffaa55f6ca35b5694864b3f4fc7b44ea89e25256ec18dabc4e54672617095617b3ac5362d229afaa85761c1a1d70df2de9892fb32c7779a66e802256124470c7ddcb661aadf2addb476b01ef2a80d97de26e2d3bc34bbe846806e62fb677a7b76c35e47ab2843f39a3a50c5f9758ddd0791928d37f25d6582b2f41813164874cb1aa86fe25e336d78b22aab22e93ea7643e309a84d6531aad3d5759875f54dc74de5343e43a5b8f4703cfe4e9f6270864eee470599a02852f2b12c350ecd8a67ac15952f76af5a624d3e49cc318fbe4967144552b0bdb3c73cb206c8960bccd98ba94e482497183aba028a603d7e8d31c8450a8a1b19b7ad35eeb6c933ac013d99e4c007f4cd9bc401fa1n
  private readonly q: bigint = 0xed185c98f324f4d6256bfa2c7e7bfab0dfd05ad320f7c6203918bf8755fd0a43n
  private readonly g: bigint = 0x8609b8ba32bc806a7139465ea9cebe3f376b050660c51c96be91feee3dff3b866dcea6b9551a6ca38ede59c6ebd34ec0bf75e51cf60d1572de8e810b62e58b6d296210d88ae79ebeb4432cb395f1b014e02ab2fb3095c59e13a1bb2bcc468ad9b838e4c08dcd8da6203661c84d9f39b700c2eee9ddab3de9cdd345ca61f39e5b0ad32cf1f252538805f56c132e8ebffaa49c6515bb09194e32efa5830546892c64e78b61219033e5e345dcc7eadbd858d13a6e008cec482a5c07a31c15a8d786885534109f5b2222cc4e208562bfeea809ff4fefe5e1ab08fb046c3f02fd432b2c4ead25916f87773cb8f303ef86e2cbebb7590252de903a4fcdd818c9ef71ce0e636f64672675c925ee6dee0980fa616042bce87720c44f7e649a41087b90f673b47b7a1019c618a7bc075166bab5f402507576906026c5558bf56a31e1743b9e67ab02b59ab1e64e4fd0afdc09c46699f1ef613dd358f313094d248ea4012c96be126451bf879403648452099a903885849f2c07bebdc15be91172ee3fa6fdn;
  private sha256(data: Uint8Array): Uint8Array {
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
    // ★ここを正しく修正★
    const blockCount = Math.ceil((len + 9) / 64);
    const blocks = new Uint8Array(blockCount * 64);
    blocks.set(data);
    blocks[len] = 0x80;
    const view = new DataView(blocks.buffer);
    // ビット長（big-endian）
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
        W[t] = (((W[t - 16] + s0) | 0) + ((W[t - 7] + s1) | 0)) >>> 0;
      }
      let a = h0,
        b = h1,
        c = h2,
        d = h3,
        e = h4,
        f = h5,
        g = h6,
        h = h7;
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 =
          (((h + S1) | 0) + (ch | 0) + (K[t] | 0) + (W[t] | 0)) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = ((S0 + maj) | 0) >>> 0;
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
    const resultView = new DataView(result.buffer);
    resultView.setUint32(0, h0, false);
    resultView.setUint32(4, h1, false);
    resultView.setUint32(8, h2, false);
    resultView.setUint32(12, h3, false);
    resultView.setUint32(16, h4, false);
    resultView.setUint32(20, h5, false);
    resultView.setUint32(24, h6, false);
    resultView.setUint32(28, h7, false);
    return result;
  }
  private inv(e: bigint, mod: bigint): bigint {
    let r0 = mod,
      r1 = e;
    let x0 = 0n,
      x1 = 1n;

    r1 = r1 % mod;
    if (r1 === 0n) return 0n;

    while (r1 !== 0n) {
      const q = r0 / r1;
      const r = r0 % r1;
      r0 = r1;
      r1 = r;
      const tmp = x0 - q * x1;
      x0 = x1;
      x1 = tmp;
    }

    if (r0 !== 1n) return 0n;
    return x0 < 0n ? x0 + mod : x0;
  }
  private modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp & 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp >>= 1n;
    }
    return result;
  }
  public BigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16).toUpperCase().padStart(64, "0");
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  public bytesToBigInt(bytes: Uint8Array): bigint {
    const len = bytes.length;
    let res = 0n;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);

    let i = 0;
    for (; i <= len - 8; i += 8) {
      res = (res << 64n) + view.getBigUint64(i);
    }
    for (; i < len; i++) {
      res = (res << 8n) + BigInt(bytes[i]);
    }
    return res;
  }
  public getkeypair(): { privatekey: Uint8Array, publickey: Uint8Array } {
    const x = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const xBigInt = this.bytesToBigInt(x);
    const yBigInt = this.modPow(this.g, xBigInt, this.p);
    
    // 384バイト（3072bit）で変換
    const hex = yBigInt.toString(16).padStart(768, "0");
    const y = new Uint8Array(384);
    for (let i = 0; i < 384; i++) {
      y[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return { privatekey: x, publickey: y };
  }
  public sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
    const x = this.bytesToBigInt(privateKey);
    
    const k = this.generateK(message, privateKey)
    
    const r = this.modPow(this.g, k, this.p) % this.q;
    const kInv = this.inv(k, this.q);
    const hash = this.bytesToBigInt(this.sha256(message));
    
    // % this.q を追加
    const s = (kInv * ((hash + r * x) % this.q)) % this.q;
    
      const sig = new Uint8Array(64);
    sig.set(this.BigintToBytes(r), 0);
    sig.set(this.BigintToBytes(s), 32);
    return sig;
  }
  public verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    const y = this.bytesToBigInt(publicKey);
    const r = this.bytesToBigInt(signature.slice(0, 32));
    const s = this.bytesToBigInt(signature.slice(32, 64));
    if (r <= 0n || r >= this.q || s <= 0n || s >= this.q) return false;
    const w = this.inv(s, this.q);
    const hash = this.bytesToBigInt(this.sha256(message));
    const u1 = (hash * w) % this.q;
    const u2 = (r * w) % this.q;
    const v = ((this.modPow(this.g, u1, this.p) * this.modPow(y, u2, this.p)) % this.p) % this.q;

    return v === r;
    
  }
  public bigintToHex(n: bigint, byteLength?: number): string {
    const hex = n.toString(16).toUpperCase();
    const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
    return hex.padStart(padLen, "0");
  }
  public hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }
  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
  const qLen = 32; // qは256bit = 32バイト

  // ステップa: h1 = hash(message)
  const h1 = this.sha256(message);

  // ステップb: V = 0x01 * 32
  let V = new Uint8Array(qLen).fill(0x01);

  // ステップc: K = 0x00 * 32
  let K = new Uint8Array(qLen).fill(0x00);

  // ステップd: K = HMAC-SHA256(K, V || 0x00 || privateKey || h1)
  K = this.hmacSha256(K, new Uint8Array([...V, 0x00, ...privateKey, ...h1])) as Uint8Array<ArrayBuffer>;

  // ステップe: V = HMAC-SHA256(K, V)
  V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;

  // ステップf: K = HMAC-SHA256(K, V || 0x01 || privateKey || h1)
  K = this.hmacSha256(K, new Uint8Array([...V, 0x01, ...privateKey, ...h1])) as Uint8Array<ArrayBuffer>;

  // ステップg: V = HMAC-SHA256(K, V)
  V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;

  // ステップh: 候補を生成してqの範囲に収まるまで繰り返す
    while (true) {
      // T を空にする
      let T = new Uint8Array(0);

      // T が qLen 以上になるまで V を追加
      while (T.length < qLen) {
        V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
        T = new Uint8Array([...T, ...V]);
      }

      // k候補を取り出す
      const k = this.bytesToBigInt(T.slice(0, qLen));

      // 1 <= k <= q-1 なら採用
      if (k >= 1n && k < this.q) {
        return k;
      }

      // 範囲外なら K, V を更新して再試行
      K = this.hmacSha256(K, new Uint8Array([...V, 0x00])) as Uint8Array<ArrayBuffer>;
      V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    }
  }
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = kPadded.map((b) => b ^ 0x36);
    const opad = kPadded.map((b) => b ^ 0x5c);
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }
  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }
  public bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }
  public hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  public getKeypairhex(): {privatekey: string, publickey: string} {
    const { privatekey, publickey } = this.getkeypair();
    return {
      privatekey: this.bigintToHex(this.bytesToBigInt(privatekey)),
      publickey: this.bigintToHex(this.bytesToBigInt(publickey))
    }
  }
  public signhex(message: Uint8Array, privateKey: string): string {
    const privateKeyBytes = this.hexToBytes(privateKey);
    const signature = this.sign(message, privateKeyBytes);
    return this.bytesToHex(signature);
  }
  public verifyhex(message: Uint8Array, signatureHex: string, publicKeyHex: string): boolean {
    const signatureBytes = this.hexToBytes(signatureHex);
    const publicKeyBytes = this.hexToBytes(publicKeyHex);
    return this.verify(message, signatureBytes, publicKeyBytes);
  }
  public privatekeytopublickey(privateKeyHex: string): string {
    const privateKeyBytes = this.hexToBytes(privateKeyHex);
    const xBigInt = this.bytesToBigInt(privateKeyBytes);
    const yBigInt = this.modPow(this.g, xBigInt, this.p);
    return this.bigintToHex(yBigInt);
  }
  public dh (privateKeyHex: string, publicKeyHex: string): string {
    const privateKeyBytes = this.hexToBytes(privateKeyHex);
    const publicKeyBytes = this.hexToBytes(publicKeyHex);
    const xBigInt = this.bytesToBigInt(privateKeyBytes);
    const yBigInt = this.bytesToBigInt(publicKeyBytes);
    const sharedSecret = this.modPow(yBigInt, xBigInt, this.p);
    return this.bytesToHex(this.sha256(this.BigintToBytes(sharedSecret)));
  }
}

// 使用例
 
const dsaInstance = new dsa();
const ciphers = new cipher();
const encoder = new TextEncoder();
const message = encoder.encode("Hello, World!");
const key = new Uint8Array(32); // 256-bit key
globalThis.crypto.getRandomValues(key);
const encrypted = ciphers.encrypt(message, key);
console.log("Encrypted:", dsaInstance.bytesToHex(encrypted));
const decrypted = ciphers.decrypt(encrypted, key);
if (decrypted) {
  const decoder = new TextDecoder();
  console.log("Decrypted:", decoder.decode(decrypted));
}


console.time ("DSA Key Generation");
const { privatekey, publickey } = dsaInstance.getkeypair();
console.timeEnd("DSA Key Generation");
console.time("DSA Sign");
const signature = dsaInstance.sign(message, privatekey);
console.timeEnd("DSA Sign");
console.time("DSA Verify");
const isValid = dsaInstance.verify(message, signature, publickey);
console.timeEnd("DSA Verify");
console.log("Signature valid?", isValid);
console.log("Public Key (hex):", dsaInstance.bigintToHex(dsaInstance.bytesToBigInt(publickey)));
console.log("Signature r (hex):", dsaInstance.bigintToHex(dsaInstance.bytesToBigInt(signature.slice(0, 32))));
console.log("Signature s (hex):", dsaInstance.bigintToHex(dsaInstance.bytesToBigInt(signature.slice(32, 64))));
console.log("privatekey (hex):", dsaInstance.bigintToHex(dsaInstance.bytesToBigInt(privatekey)));
console.log("sign(b64):", btoa(String.fromCharCode(...signature)));
console.log("publickey(b64):", btoa(String.fromCharCode(...publickey)));
console.log("message(b64):", btoa(String.fromCharCode(...message)));
console.log("message(utf8):", new TextDecoder().decode(message));
console.log("privatekey(b64):", btoa(String.fromCharCode(...privatekey)));
// =====================================================================
// DOM操作
// =====================================================================
(() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const cipherInst = new cipher();
  const dsaInst = new dsa();

  const style = document.createElement("style");
  style.textContent = `
    *, *::before, *::after { box-sizing: border-box; touch-action: manipulation; }
    :root {
      --bg: #f7f6f3; --surface: #ffffff; --border: #e2e0db;
      --text: #1a1917; --muted: #8a8780;
      --success: #2d6a4f; --error: #c1121f;
      --mono: 'JetBrains Mono', monospace; --sans: 'DM Sans', sans-serif;
    }
    body { margin:0; padding:0; background:var(--bg); color:var(--text); font-family:var(--sans); font-size:14px; line-height:1.6; min-height:100vh; }
    #ct-header { padding:32px 40px 24px; border-bottom:1px solid var(--border); background:var(--surface); }
    #ct-header h1 { margin:0; font-family:var(--mono); font-size:18px; font-weight:400; letter-spacing:0.05em; }
    #ct-header p { margin:4px 0 0; font-size:12px; color:var(--muted); font-family:var(--mono); }
    #ct-tabs { display:flex; padding:0 40px; background:var(--surface); border-bottom:1px solid var(--border); }
    .ct-tab { padding:12px 20px; font-family:var(--mono); font-size:12px; color:var(--muted); cursor:pointer; border:none; background:none; border-bottom:2px solid transparent; margin-bottom:-1px; transition:color 0.15s,border-color 0.15s; letter-spacing:0.05em; }
    .ct-tab:hover { color:var(--text); }
    .ct-tab.active { color:var(--text); border-bottom-color:var(--text); }
    #ct-panels { max-width:720px; margin:0 auto; padding:32px 40px; }
    .ct-panel { display:none; }
    .ct-panel.active { display:block; }
    .ct-field { margin-bottom:20px; }
    .ct-label { display:block; font-family:var(--mono); font-size:11px; font-weight:500; letter-spacing:0.08em; color:var(--muted); text-transform:uppercase; margin-bottom:6px; }
    .ct-input, .ct-textarea { width:100%; padding:10px 12px; font-family:var(--mono); font-size:12px; line-height:1.6; color:var(--text); background:var(--surface); border:1px solid var(--border); border-radius:4px; outline:none; resize:vertical; transition:border-color 0.15s; }
    .ct-input:focus, .ct-textarea:focus { border-color:var(--text); }
    .ct-textarea { min-height:72px; }
    .ct-output { width:100%; padding:10px 12px; font-family:var(--mono); font-size:11px; line-height:1.7; color:var(--text); background:var(--bg); border:1px solid var(--border); border-radius:4px; word-break:break-all; min-height:40px; white-space:pre-wrap; }
    .ct-output-wrap { position:relative; }
    .ct-copy { position:absolute; top:6px; right:6px; padding:3px 8px; font-family:var(--mono); font-size:10px; color:var(--muted); background:var(--surface); border:1px solid var(--border); border-radius:3px; cursor:pointer; }
    .ct-copy:hover { color:var(--text); border-color:var(--text); }
    .ct-btn { padding:10px 20px; font-family:var(--mono); font-size:12px; font-weight:500; color:var(--bg); background:var(--text); border:none; border-radius:4px; cursor:pointer; transition:opacity 0.15s; }
    .ct-btn:hover { opacity:0.8; }
    .ct-badge { display:inline-block; padding:4px 10px; font-family:var(--mono); font-size:11px; font-weight:500; border-radius:3px; margin-top:8px; }
    .ct-badge.valid { background:#d8f3dc; color:var(--success); }
    .ct-badge.invalid { background:#ffe0e0; color:var(--error); }
    @media (max-width:600px) { #ct-header, #ct-tabs { padding-left:20px; padding-right:20px; } #ct-panels { padding:24px 20px; } }
  `;
  document.head.appendChild(style);

  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&display=swap";
  document.head.appendChild(link);

  // ── ヘルパー ──
  const el = (tag: string, cls = "", text = "") => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text) e.textContent = text;
    return e;
  };
  const addField = (parent: HTMLElement, labelText: string, child: HTMLElement) => {
    const f = el("div", "ct-field");
    f.appendChild(el("label", "ct-label", labelText));
    f.appendChild(child);
    parent.appendChild(f);
    return child;
  };
  const addOutput = (parent: HTMLElement, labelText: string) => {
    const f = el("div", "ct-field");
    f.appendChild(el("label", "ct-label", labelText));
    const wrap = el("div", "ct-output-wrap");
    const out = el("div", "ct-output"); out.textContent = "—";
    const copy = el("button", "ct-copy", "copy");
    copy.addEventListener("click", () => {
      if (out.textContent === "—") return;
      navigator.clipboard.writeText(out.textContent ?? "").then(() => {
        copy.textContent = "copied";
        setTimeout(() => copy.textContent = "copy", 1200);
      });
    });
    wrap.appendChild(out); wrap.appendChild(copy);
    f.appendChild(wrap); parent.appendChild(f);
    return out;
  };
  const addBtn = (parent: HTMLElement, text: string, onClick: () => void) => {
    const f = el("div", "ct-field");
    const b = el("button", "ct-btn", text);
    b.addEventListener("click", onClick);
    f.appendChild(b); parent.appendChild(f);
    return b;
  };
  const mkTextarea = (placeholder = "") => {
    const t = el("textarea", "ct-textarea") as HTMLTextAreaElement;
    t.placeholder = placeholder; return t;
  };
  const mkInput = (placeholder = "") => {
    const i = el("input", "ct-input") as HTMLInputElement;
    i.type = "text"; i.placeholder = placeholder; return i;
  };

  // ── ヘッダー ──
  const header = el("div"); header.id = "ct-header";
  header.innerHTML = `<h1>DSAとAESもどき</h1><p>eccがすでにあるのに...</p>`;
  document.body.appendChild(header);

  // ── タブバー ──
  const tabBar = el("div"); tabBar.id = "ct-tabs";
  document.body.appendChild(tabBar);

  // ── パネル ──
  const panelContainer = el("div"); panelContainer.id = "ct-panels";
  document.body.appendChild(panelContainer);

  const tabs: HTMLElement[] = [];
  const panelEls: HTMLElement[] = [];

  const addTab = (name: string, build: (p: HTMLElement) => void) => {
    const tab = el("button", "ct-tab", name);
    tabBar.appendChild(tab); tabs.push(tab);
    const panel = el("div", "ct-panel");
    panelContainer.appendChild(panel); panelEls.push(panel);
    build(panel);
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panelEls.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      panel.classList.add("active");
    });
  };

  // ── keygen ──
  addTab("keygen", p => {
    addBtn(p, "鍵を生成する", () => {
      const kp = dsaInst.getkeypair();
      privOut.textContent = dsaInst.bigintToHex(dsaInst.bytesToBigInt(kp.privatekey));
      pubOut.textContent = dsaInst.bigintToHex(dsaInst.bytesToBigInt(kp.publickey));
    });
    const privOut = addOutput(p, "private key (hex)");
    const pubOut = addOutput(p, "public key (hex)");
  });

  // ── priv→pub ──
  addTab("priv→pub", p => {
    const privIn = mkInput("秘密鍵のhex (64文字)");
    addField(p, "private key (hex)", privIn);
    const out = addOutput(p, "public key (hex)");
    addBtn(p, "公開鍵を導出する", () => {
      try {
        out.textContent = dsaInst.privatekeytopublickey(privIn.value.trim());
      } catch(e: any) { out.textContent = "エラー: " + e.message; }
    });
  });

  // ── encrypt ──
  addTab("encrypt", p => {
    const ta = mkTextarea("暗号化するテキスト");
    addField(p, "plaintext", ta);
    const keyIn = mkInput("暗号鍵 (64文字のhex = 32バイト)");
    addField(p, "cipher key (hex)", keyIn);
    const out = addOutput(p, "ciphertext (base64)");
    addBtn(p, "暗号化する", () => {
      try {
        const key = dsaInst.hexToBytes(keyIn.value.trim());
        const ct = cipherInst.encrypt(enc.encode(ta.value), key);
        out.textContent = btoa(String.fromCharCode(...ct));
      } catch(e: any) { out.textContent = "エラー: " + e.message; }
    });
  });

  // ── decrypt ──
  addTab("decrypt", p => {
    const ta = mkTextarea("Base64の暗号文");
    addField(p, "ciphertext (base64)", ta);
    const keyIn = mkInput("暗号鍵 (64文字のhex = 32バイト)");
    addField(p, "cipher key (hex)", keyIn);
    const out = addOutput(p, "plaintext");
    addBtn(p, "復号する", () => {
      try {
        const key = dsaInst.hexToBytes(keyIn.value.trim());
        const ct = Uint8Array.from(atob(ta.value.trim()), c => c.charCodeAt(0));
        const pt = cipherInst.decrypt(ct, key);
        out.textContent = pt ? dec.decode(pt) : "復号失敗（改ざん検知）";
      } catch(e: any) { out.textContent = "エラー: " + e.message; }
    });
  });

  // ── sign ──
  addTab("sign", p => {
    const ta = mkTextarea("署名するメッセージ");
    addField(p, "message", ta);
    const privIn = mkInput("秘密鍵のhex (64文字)");
    addField(p, "private key (hex)", privIn);
    const out = addOutput(p, "signature (hex)");
    addBtn(p, "署名する", () => {
      try {
        const sig = dsaInst.signhex(enc.encode(ta.value), privIn.value);
        out.textContent = sig;
      } catch(e: any) { out.textContent = "エラー: " + e.message; }
    });
  });

  // ── verify ──
  addTab("verify", p => {
    const ta = mkTextarea("検証するメッセージ");
    addField(p, "message", ta);
    const sigIn = mkInput("署名のhex");
    addField(p, "signature (hex)", sigIn);
    const pubIn = mkInput("公開鍵のhex");
    addField(p, "public key (hex)", pubIn);
    const f = el("div", "ct-field");
    const badge = el("div");
    const b = el("button", "ct-btn", "検証する");
    b.addEventListener("click", () => {
      try {
        const valid = dsaInst.verifyhex(enc.encode(ta.value), sigIn.value, pubIn.value);
        badge.innerHTML = `<span class="ct-badge ${valid ? "valid" : "invalid"}">${valid ? "✓ 署名有効" : "✗ 署名無効"}</span>`;
      } catch(e: any) {
        badge.innerHTML = `<span class="ct-badge invalid">エラー: ${(e as any).message}</span>`;
      }
    });
    f.appendChild(b); f.appendChild(badge);
    p.appendChild(f);
  });
  // ── dh ──
  addTab("dh", p => {
    const privIn = mkInput("自分の秘密鍵 (hex)");
    addField(p, "private key (hex)", privIn);
    const pubIn = mkInput("相手の公開鍵 (hex)");
    addField(p, "peer public key (hex)", pubIn);
    const out = addOutput(p, "shared secret (hex)");
    addBtn(p, "共有秘密を導出する", () => {
      try {
        out.textContent = dsaInst.dh(privIn.value.trim(), pubIn.value.trim());
      } catch(e: any) { out.textContent = "エラー: " + e.message; }
    });
  });

  // 最初のタブをアクティブに
  tabs[0]?.classList.add("active");
  panelEls[0]?.classList.add("active");
})();
