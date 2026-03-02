
class shunoa {
  // --- 定数定義 ---
  private readonly p: bigint = BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF");
  private readonly g: bigint = 2n;
  private readonly q: bigint = BigInt("0x7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD1128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DAFB312F3F637A262174D31BEEB585FFADDB7A035BF6F71C35FDAD44CFCAD74F8F25FF32494332A8F66EE61EE1003E5C50B1DF02CC6A241B0E1B19B0E62AD1A9256ED269339661A775E125D67E916E91EED1D6CB16E80E31795DCEB94B3B3B36B3B3B33BFFFFFFFFFFFFFFFF");

  constructor() {}

  // --- 変換ユーティリティ ---
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

  private bigintToUint8Array(bn: bigint): Uint8Array {
    let hex = bn.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const len = hex.length / 2;
    const u8 = new Uint8Array(256); // 2048bit = 256byte
    for (let i = 0; i < len; i++) {
      u8[256 - len + i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return u8;
  }

  private uint8ArrayToBigInt(u8: Uint8Array): bigint {
    let hex = "";
    u8.forEach(b => hex += b.toString(16).padStart(2, "0"));
    return BigInt("0x" + hex);
  }

  private hashToBigInt(data: Uint8Array): bigint {
    const hashBuffer =  this.sha256(data);
    return this.uint8ArrayToBigInt(new Uint8Array(hashBuffer));
  }

  private modExp(base: bigint, exp: bigint, mod: bigint): bigint {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) res = (res * base) % mod;
      base = (base * base) % mod;
      exp = exp / 2n;
    }
    return res;
  }

  // --- 公開メソッド ---

  /** 公開鍵の生成 */
  public  getPublicKey(privateKey: Uint8Array): Uint8Array {
    const priv = this.uint8ArrayToBigInt(privateKey);
    const pub = this.modExp(this.g, priv, this.p);
    return this.bigintToUint8Array(pub);
  }

  /** 署名の生成 (R + s = 512バイト) */
  public sign(message: string, privateKey: Uint8Array): Uint8Array {
    const priv = this.uint8ArrayToBigInt(privateKey);
    const msgData = new TextEncoder().encode(message);
    
    // 決定論的 k 生成 (RFC 6979 的アプローチ)
    const k = this.generateK(msgData, privateKey);

    const R = this.modExp(this.g, k, this.p);
    const R_bytes = this.bigintToUint8Array(R);
    
    const e = (this.hashToBigInt(new Uint8Array([...R_bytes, ...msgData]))) % this.q;
    const s = (k + (e * priv)) % this.q;

    const signature = new Uint8Array(512);
    signature.set(R_bytes, 0);
    signature.set(this.bigintToUint8Array(s), 256);
    return signature;
  }

    private generateK(message: Uint8Array, privateKey: Uint8Array): bigint {
  const qLen = Math.ceil(this.q.toString(2).length / 8);

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

  /** 署名の検証 */
  public verify(message: string, signature: Uint8Array, publicKey: Uint8Array): boolean {
    if (signature.length !== 512) return false;
    
    const pub = this.uint8ArrayToBigInt(publicKey);
    const msgData = new TextEncoder().encode(message);
    
    const R_bytes = signature.slice(0, 256);
    const s_bytes = signature.slice(256, 512);
    
    const R = this.uint8ArrayToBigInt(R_bytes);
    const s = this.uint8ArrayToBigInt(s_bytes);
    
    const e = (this.hashToBigInt(new Uint8Array([...R_bytes, ...msgData]))) % this.q;

    const leftSide = this.modExp(this.g, s, this.p);
    const rightSide = (R * this.modExp(pub, e, this.p)) % this.p;

    return leftSide === rightSide;
  }
}

const shunoaInstance = new shunoa();
const privateKey = new Uint8Array(32)
globalThis.crypto.getRandomValues(privateKey);
const publicKey = shunoaInstance.getPublicKey(privateKey);
const message = "Hello, Shunoa!";
const signature = shunoaInstance.sign(message, privateKey);
const isValid = shunoaInstance.verify(message, signature, publicKey);
console.log("Public Key:", Buffer.from(publicKey).toString("hex"));
console.log("Signature:", Buffer.from(signature).toString("hex"));
console.log("Verification Result:", isValid);
console.log("改ざん検査 (メッセージ変更):", shunoaInstance.verify(message + "!", signature, publicKey));
console.log("改ざん検査 (署名変更):", shunoaInstance.verify(message, new Uint8Array(signature.map(b => b ^ 0xFF)), publicKey));
console.log("改ざん検査 (公開鍵変更):", shunoaInstance.verify(message, signature, new Uint8Array(publicKey.map(b => b ^ 0xFF))));
console.log("privateKey:", Buffer.from(privateKey).toString("hex"));