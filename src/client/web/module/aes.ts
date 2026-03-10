export class AES {
  // 環境に合わせて crypto を取得
  private get crypto() {
    if (typeof window !== "undefined" && window.crypto) {
      return window.crypto;
    }
    // Node.js の WebCrypto を動的に読み込む（あるいは global.crypto を使用）
    return require("node:crypto").webcrypto as Crypto;
  }

  public async encrypt(
    plaintext: Uint8Array,
    keyBuffer: Uint8Array,
  ): Promise<string> {
    const cryptoKey = await this.crypto.subtle.importKey(
      "raw",
      keyBuffer as Uint8Array<ArrayBuffer>,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );

    const iv = this.crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await this.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      cryptoKey,
      plaintext as Uint8Array<ArrayBuffer>,
    );

    const result = new Uint8Array(iv.length + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), iv.length);

    // Node.js/ブラウザ両対応の Base64 変換
    if (typeof btoa === "function") {
      return btoa(String.fromCharCode(...result));
    } else {
      return Buffer.from(result).toString("base64");
    }
  }

  public async decrypt(
    base64Cipher: string,
    keyBuffer: Uint8Array,
  ): Promise<Uint8Array<ArrayBuffer>> {
    // Node.js/ブラウザ両対応のバイナリ復元
    let packet: Uint8Array;
    if (typeof atob === "function") {
      const binaryStr = atob(base64Cipher);
      packet = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++)
        packet[i] = binaryStr.charCodeAt(i);
    } else {
      packet = new Uint8Array(Buffer.from(base64Cipher, "base64"));
    }

    const cryptoKey = await this.crypto.subtle.importKey(
      "raw",
      keyBuffer as Uint8Array<ArrayBuffer>,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    const iv = packet.slice(0, 12);
    const ciphertext = packet.slice(12);

    try {
      const decrypted = await this.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        ciphertext,
      );
      return new Uint8Array(decrypted) as Uint8Array<ArrayBuffer>;
    } catch (e) {
      throw new Error("Decryption failed. Invalid key or corrupted data.");
    }
  }
}
