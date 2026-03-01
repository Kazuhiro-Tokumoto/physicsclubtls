class dsa{
 // DSA Parameters (p=1024bit, q=160bit)
private p = 0x9d439370b2865b889a66f55dc221ef308585d773ec6834f1f1b14a88783480c4d6640d33ee9ad5d64e7ac573a0e19beb51ae8d26f4be366ff103ef35232721b31a2acca58ab8b684c94299e3b558e027b00917d96105d4d36e1660d02a0fff61855668ec198cd472658a0f5b407d80dda522cf9dc3d2dc7358a2e165b0aa28d1n;
private q = 0xbe373dcf4e8a5f034b06222120384bacf5cb7d71n;
private g = 0x8e3d93281c940f118862e7bbe8a3d294e64e3f4d02284538a1d770dc1b88db4457b811fbacd99383bec6526170bad9ee22dc1dbb2045d1cf1af0a5fdeb0d7155732ed1468307f9512737801aac71808081548f972a11fbdb4b6726fedf44dc1e0fc329f49993bc2f0381945ddb38d70687a4afebc9871cff7b65be8eab17c6f1n;

    private modexp(base: bigint, exp: bigint, mod: bigint): bigint {
        let result: bigint = 1n;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2n == 1n) {
                result = (result * base) % mod;
            }
            exp = exp >> 1n;
            base = (base * base) % mod;
        }
        return result;
    }

    private async hashMessage(message: string): Promise<bigint> {
        const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(message));
        const hashHex = Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0')).join('');
        return BigInt('0x' + hashHex);
    }

    private randomBigInt(): bigint {
        return globalThis.crypto.getRandomValues(new Uint8Array(32))
            .reduce((acc, val) => (acc << 8n) + BigInt(val), 0n);
    }

    public generateKey(): { privateKey: bigint, publicKey: bigint } {
        const privateKey = (this.randomBigInt() % (this.q - 1n)) + 1n; // ✅ 1以上
        const publicKey = this.modexp(this.g, privateKey, this.p);
        return { privateKey, publicKey };
    }

    public async sign(message: string, privateKey: bigint): Promise<{ r: bigint, s: bigint }> {
        const k = (this.randomBigInt() % (this.q - 1n)) + 1n; // ✅ 1以上
        const r = this.modexp(this.g, k, this.p) % this.q;
        const hash = await this.hashMessage(message); // ✅ await
        const kInv = this.modexp(k, this.q - 2n, this.q); // ✅ k の逆元
        const s = (kInv * (hash + privateKey * r)) % this.q; // ✅ 正しい式
        if (s === 0n) return this.sign(message, privateKey); // ✅ s が 0 の場合は再生成
        if (r === 0n) return this.sign(message, privateKey); // ✅ r が 0 の場合も再生成
        return { r, s };
    }

    public async verify(message: string, signature: { r: bigint, s: bigint }, publicKey: bigint): Promise<boolean> {
        const { r, s } = signature;
        if (r <= 0n || r >= this.q || s <= 0n || s >= this.q) return false;
        const hash = await this.hashMessage(message); // ✅ await
        const w = this.modexp(s, this.q - 2n, this.q);
        const u1 = (hash * w) % this.q;
        const u2 = (r * w) % this.q;
        const v = ((this.modexp(this.g, u1, this.p) * this.modexp(publicKey, u2, this.p)) % this.p) % this.q;
        return v === r;
    }
}
const dsaInstance = new dsa();
const keys = dsaInstance.generateKey();
const message = "Hello, DSA!";
console.log("Private Key:", keys.privateKey.toString(16));
console.log("Public Key:", keys.publicKey.toString(16));

dsaInstance.sign(message, keys.privateKey).then(signature => {
    console.log("Signature:", signature);
    dsaInstance.verify(message, signature, keys.publicKey).then(isValid => {
        console.log("Signature valid:", isValid);
    }
    );
});