// ecsh_optimized.ts — P-256 ECDSA 極限最適化版
// 最適化サマリ:
//   addPointsJacobian : mod 2回削減 (S1,S2,X3,Y3,Z3 の中間mod統合)
//   doubleJacobian    : 計算順序整理、mod削減
//   hmacSha256        : map() → for ループ (GC圧力削減)
//   generateK         : spread演算子 → concat() (O(n)コピー削減)
//   scalarMult        : テーブルの [P[0],P[1],1n] 生成を1回に
//   bytesToBigInt     : 変更なし (既に最速実装)
//   sha256            : 変更なし (既に最速実装)

export class ecsh {
  private readonly P: bigint =
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  private readonly a: bigint =
    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn;
  private readonly b: bigint =
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
  private readonly N: bigint =
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  private readonly G: [bigint, bigint] = [
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  ];

  // ─── 事前計算テーブル (G用, w=8) ───────────────────────────────────────
  // G_precomp_window[i][j] = j * 2^(8i) * G
  private readonly G_precomp_window: [bigint, bigint, bigint][][] = (() => {
    const table: [bigint, bigint, bigint][][] = [];
    let base: [bigint, bigint, bigint] = [this.G[0], this.G[1], 1n];
    for (let i = 0; i < 32; i++) {
      const row: [bigint, bigint, bigint][] = new Array(256);
      row[0] = [0n, 1n, 0n]; // 単位元
      row[1] = base;
      for (let j = 2; j < 256; j++) {
        row[j] = this.addPointsJacobian(row[j - 1], base);
      }
      table.push(row);
      for (let j = 0; j < 8; j++) base = this.doubleJacobian(base);
    }
    return table;
  })();

  // ─── ヤコビアン点加算 (最適化版) ────────────────────────────────────────
  // 変更点:
  //   S1 = Y1*Z2*Z2Z2 % p     (旧: Y1*Z2%p*Z2Z2%p → mod 2回 → 1回に)
  //   S2 = Y2*Z1*Z1Z1 % p     (同上)
  //   X3 = (R²-HHH-2*U1HH+4p) % p  (旧: mod(R*R%p - ...) → mod 2回 → 1回に)
  //   Y3 = (R*(U1HH-X3+p) - S1*HHH + 2p²) % p  (2mod → 1mod)
  //   Z3 = H*Z1*Z2 % p        (旧: H*Z1%p*Z2%p → mod 2回 → 1回に)
  private addPointsJacobian(
    P: [bigint, bigint, bigint],
    Q: [bigint, bigint, bigint]
  ): [bigint, bigint, bigint] {
    const [X1, Y1, Z1] = P;
    const [X2, Y2, Z2] = Q;
    if (Z1 === 0n) return Q;
    if (Z2 === 0n) return P;

    const p = this.P;

    const Z1Z1 = Z1 * Z1 % p;
    const Z2Z2 = Z2 * Z2 % p;
    const U1   = X1 * Z2Z2 % p;
    const U2   = X2 * Z1Z1 % p;
    // ★ mod 2回 → 1回
    const S1   = Y1 * Z2 * Z2Z2 % p;
    const S2   = Y2 * Z1 * Z1Z1 % p;

    const H = (U2 - U1 + p) % p;
    const R = (S2 - S1 + p) % p;

    if (H === 0n) {
      if (R === 0n) return this.doubleJacobian(P);
      return [0n, 1n, 0n];
    }

    const HH   = H * H % p;
    const HHH  = H * HH % p;
    const U1HH = U1 * HH % p;

    // ★ X3: mod 2回 → 1回 (4pを足して負を回避)
    const X3 = (R * R - HHH - 2n * U1HH + 4n * p) % p;
    // ★ Y3: mod 2回 → 1回 (2p²を足して負を回避)
    //   R < p, (U1HH-X3+p) < 2p → 積 < 2p²
    //   S1 < p, HHH < p → S1*HHH < p²
    //   差 ∈ (-p², 2p²) → +2p² で確実に正
    const Y3 = (R * (U1HH - X3 + p) - S1 * HHH + 2n * p * p) % p;
    // ★ Z3: mod 2回 → 1回
    const Z3 = H * Z1 * Z2 % p;

    return [X3, Y3, Z3];
  }

  // ─── ヤコビアン点2倍算 ─────────────────────────────────────────────────
  // a=-3専用の最適化済み実装を維持しつつmod削減
  private doubleJacobian(P: [bigint, bigint, bigint]): [bigint, bigint, bigint] {
    const [X, Y, Z] = P;
    if (Z === 0n) return P;

    const p = this.P;
    const YY   = Y * Y % p;
    const YYYY = YY * YY % p;
    const ZZ   = Z * Z % p;
    const S    = 4n * X * YY % p;
    // a=-3 専用: M = 3*(X+ZZ)*(X-ZZ)
    const M    = 3n * ((X + ZZ) % p) * ((X - ZZ + p) % p) % p;

    // ★ X3: +2p で負を回避して1回のmod
    const X3 = (M * M - 2n * S + 2n * p) % p;
    // ★ Y3: 計算順序を整理
    const Y3 = (M * ((S - X3 + p) % p) - 8n * YYYY + 8n * p) % p;
    const Z3 = 2n * Y * Z % p;

    return [X3, Y3, Z3];
  }

  // ─── アフィン変換 ───────────────────────────────────────────────────────
  private toAffine(P: [bigint, bigint, bigint]): [bigint, bigint] {
    if (P[2] === 0n) return [0n, 0n];
    const invZ  = this.inv(P[2], this.P);
    const invZ2 = invZ * invZ % this.P;
    const invZ3 = invZ2 * invZ % this.P;
    return [P[0] * invZ2 % this.P, P[1] * invZ3 % this.P];
  }

  // ─── G倍算 (事前計算テーブル, w=8) ─────────────────────────────────────
  private scalarMultG(k: bigint): [bigint, bigint] {
    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = 0; i < 256; i += 8) {
      const win = Number((k >> BigInt(i)) & 0xffn);
      if (win > 0) {
        R = this.addPointsJacobian(R, this.G_precomp_window[i >> 3][win]);
      }
    }
    return this.toAffine(R);
  }

  // ─── 一般点倍算 (ヤコビアン w=4) ────────────────────────────────────────
  // ★ テーブルの baseJ を1回だけ生成 (旧実装は毎ループ[P[0],P[1],1n]生成)
  public scalarMult(k: bigint, P: [bigint, bigint]): [bigint, bigint] {
    const w = 4;
    const windowSize = 1 << w; // 16
    const baseJ: [bigint, bigint, bigint] = [P[0], P[1], 1n];
    const table: [bigint, bigint, bigint][] = new Array(windowSize);
    table[0] = [0n, 1n, 0n];
    table[1] = baseJ;
    for (let i = 2; i < windowSize; i++) {
      table[i] = this.addPointsJacobian(table[i - 1], baseJ);
    }

    let R: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = 256 - w; i >= 0; i -= w) {
      for (let j = 0; j < w; j++) R = this.doubleJacobian(R);
      const win = Number((k >> BigInt(i)) & 0xfn);
      if (win > 0) R = this.addPointsJacobian(R, table[win]);
    }
    return this.toAffine(R);
  }

  // ─── Shamir's trick (G側テーブル流用 + Q側ヤコビアンw=4) ────────────────
  private shamirsMult(
    k1: bigint,
    _P1: [bigint, bigint], // G固定なのでテーブルを直接使う
    k2: bigint,
    P2: [bigint, bigint]
  ): [bigint, bigint] {
    // G側
    let R1: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = 0; i < 256; i += 8) {
      const win = Number((k1 >> BigInt(i)) & 0xffn);
      if (win > 0) {
        R1 = this.addPointsJacobian(R1, this.G_precomp_window[i >> 3][win]);
      }
    }

    // Q側 (w=4)
    const w = 4;
    const windowSize = 1 << w;
    const baseJ: [bigint, bigint, bigint] = [P2[0], P2[1], 1n];
    const table: [bigint, bigint, bigint][] = new Array(windowSize);
    table[0] = [0n, 1n, 0n];
    table[1] = baseJ;
    for (let i = 2; i < windowSize; i++) {
      table[i] = this.addPointsJacobian(table[i - 1], baseJ);
    }

    let R2: [bigint, bigint, bigint] = [0n, 1n, 0n];
    for (let i = 256 - w; i >= 0; i -= w) {
      for (let j = 0; j < w; j++) R2 = this.doubleJacobian(R2);
      const win = Number((k2 >> BigInt(i)) & 0xfn);
      if (win > 0) R2 = this.addPointsJacobian(R2, table[win]);
    }

    return this.toAffine(this.addPointsJacobian(R1, R2));
  }

  // ─── SHA-256 (変更なし — 既に最速実装) ──────────────────────────────────
  public sha256(data: Uint8Array): Uint8Array {
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
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
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
      for (let t = 0; t < 16; t++) W[t] = view.getUint32(i + t * 4, false);
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t-15], 7) ^ rotr(W[t-15], 18) ^ (W[t-15] >>> 3);
        const s1 = rotr(W[t-2], 17) ^ rotr(W[t-2], 19) ^ (W[t-2] >>> 10);
        W[t] = (((W[t-16] + s0) | 0) + ((W[t-7] + s1) | 0)) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let t = 0; t < 64; t++) {
        const S1   = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch   = (e & f) ^ (~e & g);
        const temp1 = (((h + S1) | 0) + (ch | 0) + (K[t] | 0) + (W[t] | 0)) >>> 0;
        const S0   = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj  = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = ((S0 + maj) | 0) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0;
      h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false); rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false); rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false); rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false); rv.setUint32(28, h7, false);
    return result;
  }

  // ─── モジュラー逆元 (拡張ユークリッド) ─────────────────────────────────
  private inv(e: bigint, mod: bigint): bigint {
    let r0 = mod, r1 = ((e % mod) + mod) % mod;
    if (r1 === 0n) return 0n;
    let x0 = 0n, x1 = 1n;
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [x0, x1] = [x1, x0 - q * x1];
    }
    if (r0 !== 1n) return 0n;
    return x0 < 0n ? x0 + mod : x0;
  }

  // ─── HMAC-SHA256 (最適化: map → for) ────────────────────────────────────
  // ★ map() はコールバックオブジェクトとGCのオーバーヘッドがある
  //    forループに変えるだけで小さいが確実に速くなる
  private hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
    const BLOCK = 64;
    const k = key.length > BLOCK ? this.sha256(key) : key;
    const kPadded = new Uint8Array(BLOCK);
    kPadded.set(k);
    const ipad = new Uint8Array(BLOCK);
    const opad = new Uint8Array(BLOCK);
    // ★ map() → for (GCプレッシャー削減)
    for (let i = 0; i < BLOCK; i++) {
      ipad[i] = kPadded[i] ^ 0x36;
      opad[i] = kPadded[i] ^ 0x5c;
    }
    return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
  }

  // ─── RFC 6979 決定論的 k 生成 ────────────────────────────────────────────
  // ★ spread演算子 [...V, 0x00, ...privateKey, ...h1] → concat() 使用
  //    Uint8Array の spread は Array.from() 相当で O(n) の要素コピーが走る
  private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
    const qLen = 32; // P-256 は常に 32 バイト
    const h1   = this.sha256(message);

    let V = new Uint8Array(qLen).fill(0x01);
    let K = new Uint8Array(qLen).fill(0x00);

    // ★ spread → concat
    const zero  = new Uint8Array([0x00]);
    const one   = new Uint8Array([0x01]);

    K = this.hmacSha256(K, this.concat(V, zero, privateKey, h1)) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    K = this.hmacSha256(K, this.concat(V, one, privateKey, h1)) as Uint8Array<ArrayBuffer>;
    V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;

    while (true) {
      let T = new Uint8Array(0);
      while (T.length < qLen) {
        V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
        const next = new Uint8Array(T.length + V.length);
        next.set(T);
        next.set(V, T.length);
        T = next;
      }
      const k = this.bytesToBigInt(T.subarray(0, qLen));
      if (k >= 1n && k < this.N) return k;

      K = this.hmacSha256(K, this.concat(V, zero)) as Uint8Array<ArrayBuffer>;
      V = this.hmacSha256(K, V) as Uint8Array<ArrayBuffer>;
    }
  }

  // ─── concat (変更なし) ───────────────────────────────────────────────────
  private concat(...arrays: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }

  // ─── 署名 (内部) ─────────────────────────────────────────────────────────
  private signtobigint(
    message: Uint8Array,
    privateKey: string
  ): { R: [bigint, bigint]; s: bigint } {
    const privKeyBytes = this.BigintToBytes(this.hexToBigInt(privateKey));
    const k       = this.generateK(message, privKeyBytes);
    const privKey = this.hexToBigInt(privateKey);
    const R       = this.scalarMultG(k);
    const r       = R[0];
    const e = this.bytesToBigInt(
      this.sha256(this.concat(message, this.BigintToBytes(r)))
    ) % this.N;
    const s = ((k - e * privKey) % this.N + this.N) % this.N;
    if (r === 0n || s === 0n) {
      throw new Error("署名値が0になりました。アルゴリズム要件により失敗とみなします。");
    }
    return { R, s };
  }

  // ─── 署名 (公開) ─────────────────────────────────────────────────────────
  public sign(message: Uint8Array, privateKey: string): string {
    const { R, s } = this.signtobigint(message, privateKey);
    return this.bigintToHex(R[0]) + this.bigintToHex(R[1]) + this.bigintToHex(s);
  }

  // ─── 検証 ────────────────────────────────────────────────────────────────
  public _prof: Record<string, number> = {};
  private _profTmp = 0;
  private _profStart(_name: string) { this._profTmp = performance.now(); }
  private _profEnd(name: string) {
    this._prof[name] = (this._prof[name] ?? 0) + performance.now() - this._profTmp;
  }

  public verify(
    message: Uint8Array,
    signature: string,
    publicKey: string
  ): boolean {
    this._profStart("decompress_pubkey");
    const uncompressed = publicKey.length === 66 ? this.decompressPublicKey(publicKey) : publicKey;
    const px = this.hexToBigInt(uncompressed.slice(0, 64));
    const py = this.hexToBigInt(uncompressed.slice(64, 128));
    this._profEnd("decompress_pubkey");

    this._profStart("isPointOnCurve");
    if (!this.isPointOnCurve([px, py])) throw new Error("無効な公開鍵: 曲線上にありません");
    this._profEnd("isPointOnCurve");

    const Rx = this.hexToBigInt(signature.slice(0, 64));
    const Ry = this.hexToBigInt(signature.slice(64, 128));
    const s  = this.hexToBigInt(signature.slice(128, 192));
    const R: [bigint, bigint] = [Rx, Ry];

    if (Rx <= 0n || Rx >= this.N || s <= 0n || s >= this.N) return false;

    this._profStart("hash_e");
    const e = this.bytesToBigInt(
      this.sha256(this.concat(message, this.BigintToBytes(Rx)))
    ) % this.N;
    this._profEnd("hash_e");

    this._profStart("shamirsMult");
    const result = this.shamirsMult(s, this.G, e, [px, py]);
    this._profEnd("shamirsMult");

    return result[0] === R[0] && result[1] === R[1];
  }

  // ─── ユーティリティ ──────────────────────────────────────────────────────
  public isPointOnCurve(P: [bigint, bigint]): boolean {
    const [x, y] = P;
    if (x === 0n && y === 0n) return false;
    const p = this.P;
    const left  = y * y % p;
    const right = (x * x * x + this.a * x + this.b) % p;
    return left === right;
  }

  public addPoints(P: [bigint, bigint], Q: [bigint, bigint]): [bigint, bigint] {
    const [x1, y1] = P;
    const [x2, y2] = Q;
    if (x1 === 0n && y1 === 0n) return Q;
    if (x2 === 0n && y2 === 0n) return P;
    const p = this.P;
    let m: bigint;
    if (x1 === x2) {
      if (y1 !== y2 || y1 === 0n) return [0n, 0n];
      m = (3n * x1 * x1 + this.a) % p * this.inv(2n * y1 % p, p) % p;
    } else {
      m = (y2 - y1 + p) % p * this.inv((x2 - x1 + p) % p, p) % p;
    }
    const x3 = (m * m - x1 - x2 + 2n * p) % p;
    const y3 = (m * (x1 - x3 + p) - y1 + p) % p;
    return [x3, y3];
  }

  public generateKeyPair(): { privateKey: string; publicKey: string } {
    const privateKey = this.getRandomBigInt(this.N - 1n) + 1n;
    const pubPoint   = this.scalarMult(privateKey, this.G);
    return {
      privateKey: this.bigintToHex(privateKey),
      publicKey:  this.bigintToHex(pubPoint[0]) + this.bigintToHex(pubPoint[1]),
    };
  }

  public privateKeyToPublicKey(privateKeyHex: string): { compressed: string; uncompressed: string } {
    const privKey = this.hexToBigInt(privateKeyHex);
    if (privKey <= 0n || privKey >= this.N) throw new Error("無効な秘密鍵");
    const pubPoint   = this.scalarMult(privKey, this.G);
    const uncompressed = this.bigintToHex(pubPoint[0]) + this.bigintToHex(pubPoint[1]);
    return { compressed: uncompressed, uncompressed };
  }

  public ecdh(privateKeyHex: string, peerPublicKeyHex: string): string {
    const privKey = this.hexToBigInt(privateKeyHex);
    if (privKey <= 0n || privKey >= this.N) throw new Error("無効な秘密鍵");
    const uncompressed = peerPublicKeyHex.length === 66
      ? this.decompressPublicKey(peerPublicKeyHex)
      : peerPublicKeyHex;
    const peerX = this.hexToBigInt(uncompressed.slice(0, 64));
    const peerY = this.hexToBigInt(uncompressed.slice(64, 128));
    if (!this.isPointOnCurve([peerX, peerY])) throw new Error("無効な公開鍵");
    const sharedPoint = this.scalarMult(privKey, [peerX, peerY]);
    return this.bigintToHex(sharedPoint[0]);
  }

  public decompressPublicKey(compressed: string): string {
    const prefix = compressed.slice(0, 2);
    const x      = this.hexToBigInt(compressed.slice(2, 66));
    const rhs    = (x * x * x + this.a * x + this.b) % this.P;
    const y      = this.modSqrt(rhs);
    const wantOdd = prefix === "03";
    const finalY  = (y % 2n === 1n) === wantOdd ? y : this.P - y;
    return this.bigintToHex(x) + this.bigintToHex(finalY);
  }

  // ─── プリミティブ ────────────────────────────────────────────────────────
  private bigintToHex(n: bigint): string {
    return n.toString(16).toUpperCase().padStart(64, "0");
  }

  private hexToBigInt(hex: string): bigint {
    return BigInt("0x" + hex);
  }

  private BigintToBytes(n: bigint): Uint8Array {
    const hex = n.toString(16).toUpperCase().padStart(64, "0");
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  private bytesToBigInt(bytes: Uint8Array): bigint {
    const len  = bytes.length;
    const view = new DataView(bytes.buffer, bytes.byteOffset, len);
    let res = 0n, i = 0;
    for (; i <= len - 8; i += 8) res = (res << 64n) + view.getBigUint64(i);
    for (; i < len; i++)         res = (res << 8n)  + BigInt(bytes[i]);
    return res;
  }

  private modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp & 1n) result = result * base % mod;
      base = base * base % mod;
      exp >>= 1n;
    }
    return result;
  }

  private modSqrt(n: bigint): bigint {
    if (n === 0n) return 0n;
    if (this.modPow(n, (this.P - 1n) / 2n, this.P) !== 1n) {
      throw new Error("平方根が存在しません");
    }
    let Q = this.P - 1n, S = 0n;
    while (Q % 2n === 0n) { Q /= 2n; S++; }
    let z = 2n;
    while (this.modPow(z, (this.P - 1n) / 2n, this.P) !== this.P - 1n) z++;
    let M = S;
    let c = this.modPow(z, Q, this.P);
    let t = this.modPow(n, Q, this.P);
    let R = this.modPow(n, (Q + 1n) / 2n, this.P);
    while (true) {
      if (t === 1n) return R;
      let i = 1n, tmp = t * t % this.P;
      while (tmp !== 1n) { tmp = tmp * tmp % this.P; i++; }
      const b = this.modPow(c, 2n ** (M - i - 1n), this.P);
      M = i;
      c = b * b % this.P;
      t = t * b * b % this.P;
      R = R * b % this.P;
    }
  }

  private getRandomBigInt(max: bigint): bigint {
    const bytes = Math.ceil(max.toString(2).length / 8);
    let rand: bigint;
    do {
      const buf = new Uint8Array(bytes);
      globalThis.crypto.getRandomValues(buf);
      rand = this.bytesToBigInt(buf);
    } while (rand >= max);
    return rand;
  }
}


(() => {
  const enc = new TextEncoder();
  const dsaInst = new ecsh();

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
    #ct-tabs { display:flex; padding:0 40px; background:var(--surface); border-bottom:1px solid var(--border); overflow-x:auto; -webkit-overflow-scrolling:touch; scrollbar-width:none; }
    #ct-tabs::-webkit-scrollbar { display:none; }
    .ct-tab { padding:12px 20px; font-family:var(--mono); font-size:12px; color:var(--muted); cursor:pointer; border:none; background:none; border-bottom:2px solid transparent; margin-bottom:-1px; transition:color 0.15s,border-color 0.15s; letter-spacing:0.05em; white-space:nowrap; flex-shrink:0; }
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
    const out = el("div", "ct-output");
    out.textContent = "—";
    const copy = el("button", "ct-copy", "copy");
    copy.addEventListener("click", () => {
      if (out.textContent === "—") return;
      navigator.clipboard.writeText(out.textContent ?? "").then(() => {
        copy.textContent = "copied";
        setTimeout(() => copy.textContent = "copy", 1200);
      });
    });
    wrap.appendChild(out);
    wrap.appendChild(copy);
    f.appendChild(wrap);
    parent.appendChild(f);
    return out;
  };
  const addBtn = (parent: HTMLElement, text: string, onClick: () => void) => {
    const f = el("div", "ct-field");
    const b = el("button", "ct-btn", text);
    b.addEventListener("click", onClick);
    f.appendChild(b);
    parent.appendChild(f);
    return b;
  };
  const mkTextarea = (placeholder = "") => {
    const t = el("textarea", "ct-textarea") as HTMLTextAreaElement;
    t.placeholder = placeholder;
    return t;
  };
  const mkInput = (placeholder = "") => {
    const i = el("input", "ct-input") as HTMLInputElement;
    i.type = "text";
    i.placeholder = placeholder;
    return i;
  };

  // ── ヘッダー ──
  const header = el("div");
  header.id = "ct-header";
  header.innerHTML = `<h1>DSAもどき</h1><p>eccがすでにあるのに...</p>`;
  document.body.appendChild(header);

  // ── タブバー ──
  const tabBar = el("div");
  tabBar.id = "ct-tabs";
  document.body.appendChild(tabBar);

  // ── パネルコンテナ ──
  const panelContainer = el("div");
  panelContainer.id = "ct-panels";
  document.body.appendChild(panelContainer);

  const tabs: HTMLElement[] = [];
  const panelEls: HTMLElement[] = [];

  const addTab = (name: string, build: (p: HTMLElement) => void) => {
    const tab = el("button", "ct-tab", name);
    tabBar.appendChild(tab);
    tabs.push(tab);
    const panel = el("div", "ct-panel");
    panelContainer.appendChild(panel);
    panelEls.push(panel);
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
    const privOut = addOutput(p, "private key (hex)");
    const pubOut  = addOutput(p, "public key (hex)");
    addBtn(p, "鍵を生成する", () => {
      const kp = dsaInst.generateKeyPair();
      privOut.textContent = kp.privateKey;
      pubOut.textContent  = kp.publicKey;
    });
  });

  // ── priv→pub ──
  addTab("priv→pub", p => {
    const privIn = mkInput("秘密鍵のhex (64文字)");
    addField(p, "private key (hex)", privIn);
    const out = addOutput(p, "public key (hex)");
    addBtn(p, "公開鍵を導出する", () => {
      try {
        const result = dsaInst.privateKeyToPublicKey(privIn.value.trim());
        out.textContent = result.uncompressed;
      } catch (e: any) {
        out.textContent = "エラー: " + e.message;
      }
    });
  });

  // ── sign ──
  addTab("sign", p => {
    const ta     = mkTextarea("署名するメッセージ");
    addField(p, "message", ta);
    const privIn = mkInput("秘密鍵のhex (64文字)");
    addField(p, "private key (hex)", privIn);
    const out = addOutput(p, "signature (hex)");
    addBtn(p, "署名する", () => {
      try {
        const sig = dsaInst.sign(enc.encode(ta.value), privIn.value.trim());
        out.textContent = sig;
      } catch (e: any) {
        out.textContent = "エラー: " + e.message;
      }
    });
  });

  // ── verify ──
  addTab("verify", p => {
    const ta     = mkTextarea("検証するメッセージ");
    addField(p, "message", ta);
    const sigIn  = mkInput("署名のhex");
    addField(p, "signature (hex)", sigIn);
    const pubIn  = mkInput("公開鍵のhex");
    addField(p, "public key (hex)", pubIn);
    const f = el("div", "ct-field");
    const badge = el("div");
    const b = el("button", "ct-btn", "検証する");
    b.addEventListener("click", () => {
      try {
        console.time("verify");
        const valid = dsaInst.verify(enc.encode(ta.value), sigIn.value.trim(), pubIn.value.trim());
        badge.innerHTML = `<span class="ct-badge ${valid ? "valid" : "invalid"}">${valid ? "✓ 署名有効" : "✗ 署名無効"}</span>`;
        console.timeEnd("verify");
      } catch (e: any) {
        badge.innerHTML = `<span class="ct-badge invalid">エラー: ${(e as any).message}</span>`;
      }
    });
    f.appendChild(b);
    f.appendChild(badge);
    p.appendChild(f);
  });

  // ── dh ──
  addTab("dh", p => {
    const privIn = mkInput("自分の秘密鍵 (hex)");
    addField(p, "private key (hex)", privIn);
    const pubIn  = mkInput("相手の公開鍵 (hex)");
    addField(p, "peer public key (hex)", pubIn);
    const out = addOutput(p, "shared secret (hex)");
    addBtn(p, "共有秘密を導出する", () => {
      try {
        out.textContent = dsaInst.ecdh(privIn.value.trim(), pubIn.value.trim());
      } catch (e: any) {
        out.textContent = "エラー: " + e.message;
      }
    });
  });

  // 最初のタブをアクティブに
  tabs[0]?.classList.add("active");
  panelEls[0]?.classList.add("active");
})();