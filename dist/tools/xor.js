export class cipher {
    // =====================================================================
    // sha256 ばぐがおおそう
    // =====================================================================
    sha256(data) {
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
        const rotr = (x, n) => (x >>> n) | (x << (32 - n));
        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
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
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (((h + S1) | 0) + (ch | 0) + (K[t] | 0) + (W[t] | 0)) >>> 0;
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
    bigintToHex(n, byteLength) {
        const hex = n.toString(16).toUpperCase();
        const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
        return hex.padStart(padLen, "0");
    }
    BigintToBytes(n, byteLength) {
        const hex = this.bigintToHex(n, byteLength);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
    hexToBigInt(hex) {
        return BigInt("0x" + hex);
    }
    bytesToBigInt(bytes) {
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
    bytesToHex(bytes) {
        return this.bigintToHex(this.bytesToBigInt(bytes));
    }
    hexToBytes(hex) {
        return this.BigintToBytes(this.hexToBigInt(hex));
    }
    concat(...arrays) {
        const total = arrays.reduce((n, a) => n + a.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            out.set(a, offset);
            offset += a.length;
        }
        return out;
    }
    counterToBytes(n) {
        const buf = new Uint8Array(8);
        const view = new DataView(buf.buffer);
        view.setUint32(0, Math.floor(n / 0x100000000), false);
        view.setUint32(4, n >>> 0, false);
        return buf;
    }
    // ---------------------------------------------------------------------
    // 1000回ストレッチング
    // ブルートフォース対策：10000回ハッシュして鍵を強化する
    // ---------------------------------------------------------------------
    stretch(data, salt) {
        let h = this.concat(data, salt);
        for (let i = 0; i < 10000; i++) {
            h = this.hmacSha256(data, this.concat(h, salt));
        }
        return h;
    }
    // ---------------------------------------------------------------------
    // HMAC-SHA256
    // ---------------------------------------------------------------------
    hmacSha256(key, data) {
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
    hkdf(inputKey, salt, info, length) {
        const prk = this.hmacSha256(salt, inputKey);
        const out = new Uint8Array(length);
        let prev = new Uint8Array(0);
        let pos = 0;
        let counter = 1;
        while (pos < length) {
            prev = this.hmacSha256(prk, this.concat(prev, info, new Uint8Array([counter++])));
            const take = Math.min(prev.length, length - pos);
            out.set(prev.subarray(0, take), pos);
            pos += take;
        }
        return out;
    }
    // ---------------------------------------------------------------------
    // CTR モード（SHA-256 ベース）
    // ---------------------------------------------------------------------
    ctrProcess(data, key, iv) {
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
    encrypt = (rawData, key) => {
        // 鍵は32Bのみ受け付ける
        if (key.length !== 32) {
            throw new Error("鍵は32バイトにしてください");
        }
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
        // 鍵を10000回ストレッチ
        const stretchedKey = this.stretch(key, iv);
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
    decrypt = (encryptedWithIv, key) => {
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
        const stretchedKey = this.stretch(key, iv);
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
export class dsa {
    //private readonly p: bigint = 0x863a7811a995cff52cc38ccd9ff9478f00768f7e265d7f9389d697c5fb45eae78b76063fe1f406b566d3a0dedcb17211213571497e506eb586fdaea2d9625f8aa254610674178211d4eaf173c2c3c7d66a56f4f93989dc8d37953978d41618e00eb95aa2e77b7e81a0c571158f4afdfcda01fecc085ffaa55f6ca35b5694864b3f4fc7b44ea89e25256ec18dabc4e54672617095617b3ac5362d229afaa85761c1a1d70df2de9892fb32c7779a66e802256124470c7ddcb661aadf2addb476b01ef2a80d97de26e2d3bc34bbe846806e62fb677a7b76c35e47ab2843f39a3a50c5f9758ddd0791928d37f25d6582b2f41813164874cb1aa86fe25e336d78b22aab22e93ea7643e309a84d6531aad3d5759875f54dc74de5343e43a5b8f4703cfe4e9f6270864eee470599a02852f2b12c350ecd8a67ac15952f76af5a624d3e49cc318fbe4967144552b0bdb3c73cb206c8960bccd98ba94e482497183aba028a603d7e8d31c8450a8a1b19b7ad35eeb6c933ac013d99e4c007f4cd9bc401fa1n
    //private readonly q: bigint = 0xed185c98f324f4d6256bfa2c7e7bfab0dfd05ad320f7c6203918bf8755fd0a43n
    //private readonly g: bigint = 0x8609b8ba32bc806a7139465ea9cebe3f376b050660c51c96be91feee3dff3b866dcea6b9551a6ca38ede59c6ebd34ec0bf75e51cf60d1572de8e810b62e58b6d296210d88ae79ebeb4432cb395f1b014e02ab2fb3095c59e13a1bb2bcc468ad9b838e4c08dcd8da6203661c84d9f39b700c2eee9ddab3de9cdd345ca61f39e5b0ad32cf1f252538805f56c132e8ebffaa49c6515bb09194e32efa5830546892c64e78b61219033e5e345dcc7eadbd858d13a6e008cec482a5c07a31c15a8d786885534109f5b2222cc4e208562bfeea809ff4fefe5e1ab08fb046c3f02fd432b2c4ead25916f87773cb8f303ef86e2cbebb7590252de903a4fcdd818c9ef71ce0e636f64672675c925ee6dee0980fa616042bce87720c44f7e649a41087b90f673b47b7a1019c618a7bc075166bab5f402507576906026c5558bf56a31e1743b9e67ab02b59ab1e64e4fd0afdc09c46699f1ef613dd358f313094d248ea4012c96be126451bf879403648452099a903885849f2c07bebdc15be91172ee3fa6fdn;
    //private  p = 0x8acc1542ae4257bbfbae0eaba6b98891de19969c9795e09584d84e9a1a9fc88eafb87d00cf6add5d20db0bf62c5456ae1339ad32062fd5ff5fbdbbfd425310a7bc776e37440f1f0d2c3ba1bd3b65e1985dad8db67dcafd11a0dbee21c25620bb7df680e9bd10919e65d6521eed23482d0fa88ea1cf5bbc8eab61eef873ed660e92c3a6130beea53fc995cc27701e3432441ea25dc16141dcfcf21d85d66825614032978d86c752e4c0b060536bc88c400c091bb5dece675ab7e6500aebadfc02b0311add43c9add6174f3c1337a03be97ad4e6be546aee07d40945ec8dc361a2b72ed8553d6e5f9863c3651d37a4906c3b8282f3962bbf2d723f189664217588aaa4175eb12957011015fd6292a966a627158108d755928bd10987b7cce8e193f9b764c686df45f6a0f192ae81677d363c9237f4df8af097f5c348769d910ecb47f38d9a61be9cf9c4c59c3fa5ef03986540406d8bf8eade27950ff2303e746a8d4c6c739b1591f4ddc1baf498215d0d3c1d8642d5167a543b36f3a49bbebaaa4e1855d7bbf9c59b3f5143f35051a7f95febfddb95dd013e378d86b34d17a239a79ce04dbacf427960690af67acd7ac078d311d60bcf56e330c31aa0d02b07da2b213ccb7bdfc29d4152243dc6604c2c52e3601cd1830a0f9ad87dab440e7cc4c50cabb509623790e73d0567029c2ff653b51519c21cc2ef17f4e3f8363bb95bn;
    //private q = 0xef674f6a32425884f61b162b9931c3aadcfab0a6213343c02d9dff3b35afd9381c413de4924638026fdef8a405b400b22573f16e6ec2b51a99b5bc1d8efda0d331526d85f90d1a6e4d64808b2c40dba6f6838ddd704a56dc4dc52c5f73e5d98fead0a2b71ccabb830620963b9f7b0ee8253e7f34e28d06516ed46a748fdc9977n;
    //private g = 0x4abd9a344ada8567dcb2ab6d94dcf30a36c046319b359599e79da15a224428b77013442707aa2146b8769d27b92fee2650abbf4871ab7ad9da1cf55a0c86fa35e9cf84914df0d23be9fd7e39bbe24c293025e56fb9bea44bfea90fc6a906fa470a6ddbfd37d41231179ebda2033af63fba8bddc2e39b55381e01158a44a6f36d37dab3391ddce7e89d41e83e1f56af50ecf992003418fca76b76567f93b6b699a03b8c73cd645b135d49acc9d3b82df3c4eec333cd0eb5c50035fb67002e972ebba254c26f479a367e76821169e9f497e8beef2bf7ad41dd3e062045fb0fb92e5a281c1df332ed8231c6b1ef62a3f8414a1574d64d77e3e26b5000c07fd8a2047f7ed52c0ff666d6cf6a893a9f2dbe4af25e67d1e67bb2eeb19cf1cfb5fb53c0a282340e4547eb4bb6150571c88ef7993cd1189958bc3d8639460a621235a76edfb1dd93e35eaf4df7b202e1b3dd048acca9f0570da8e3c1342487743df3940ea12c837c11871f5f03cd8499153b52e9540232e5811a095b8942dff01ebd9c238509a5f1e78ff4536dc91f1f2edc0b96b7900270173d2d25457796509c7bee2711cae9c759b599ac01659834172b901ba7ad84935c0fca9bbddba402f1cde4c43210c07b42a8eddb9fd832bb01748f19ae5eeea11b53d8fb2b663317341634fe8d7bb4586f767524cc79261b62380a6351d44c72501a1f1fd699f293d7c79ben;
    // DSA Parameters (p=8192bit, q=2048bit)
    //private p = 0x949cd8ad1515c066972e769458ba02f6555be2f437cff39245eabfdc081a680462d1a79c3c950c211992073ea32057f623ef492da094bbf008ee0852b28b04bc42e0060f48e5a6f4fee9f921aca2f71a79473b4f2b885a6f575e98b3fef004ef2983dbf19fde2c3431b96e0df50b49a99071a4324f2d85ecb5964b25b1ee20e01641cdfa467c8e32fa59162bac92df62b8cce4e3d9b668177c89816a6b52dda1793cb9278ba6fdf0efb696ce34ea58ce5c9a258094e7484fe2a621d8e64976d50e75ab8e0011674f291dfb94afa8871e633d48f53181f1d1c22d3865f9fc2168f11eefb344ae75c7f0ba219eb1819f97452a6860ed07b5e41cf4dac9eea8ab1f4a3472d15d7918eaab1c3f47f34d45345295c977f324b214f726ae3c0566e12a88a9e3ccd73fc976b82127b8c9cf6b324402ca71a3db001d975c9c1f4dd395b3ed9779e377ceabaf7a172a395d5db2ab7c8a3ed9b49ae7609f4a0045714a1c940d651b7b015ac252b3d52961a43b7f0074dc89c959ad3071e2d802f872984d98ba2b0959551af455dfac031620dfe1d619acd5063df48c2f310d115a918e46a77b562091b5e8cfe9333f815cae81ca31bc245e817f09c43430cf61a26615895c0df172b8e4306dde86bdf8a0036ce03af627b9579e91a9d4d89cb415ac4be17adfc522d69c66ae2f4a2833352d6957162d24e741181fc4d8d85d7681c30af3a2a3d79fb9fcee353deb2577059f40294dc4d8631f7b0c2a2b1ffa860a788b7e3eaad413ca52b28d7da0e326a98728e754a5342ff9c693e466a7b3b6b0e360be26e19a0b56a67d2604972ec050c07f86ab470f51894fda1ce0d2c6e0a2d214250e7619268bc488ad1158c0faf833412b830adb2840fed67ca00bc0d7022c5daca195219c087072015e8e90e0f474439ba40d212b7037ef4cfbe803ddf79c07f076444643aa67a7bd90a2634bf8d8d9233e9fd981ede7510d4901c3d48a09522c8325c5d0f9557bcc5141ba1cd9009a506f1de74c80a033b6bda84793548327ace7a8001323aec23bf0b5db5bfda8e0dbbdb61582d47ea268d6d1726dc5f1b8c7bf3080cab3652d695a4d2f9da5a00153880604711b0d8067acb1f38bd923d2610fc1c1a3bf6f2d455b03f349ea3bbfcae218cb1baffaaf510574449d8fb018c2f8d3b9318d35ff05d74af7cecbad9026554d818493b3a45557dc5aac64c3264527dbe2065c7b570ba9e8f55ca79eae69f19e98c6d5dd16d18603b24bff9b9028032d0a153b74ea8f28bb007ad843a18a2336dc488566c1e5b9a348782858ba05f589faaaf5a4bd35b6b5f19a2f222533e56a9276cae8851f1cfc1312ec2b067856ff358654f793a34b0e5e0df06e01530619045fbfb41494a15aeb994a955a9e8225a915e4fafa2550fd3780ec934a9e1e984d46ba64161060c65c0851c38198cdn;
    //private q = 0xc4b357a7b77bcfb07e2efc27d98222ae69e177de71e3465255dd25284237259c18d87f8960704e3f1b870f7b533295bebc39f7be9f3789c37891f59bed1dd371db71383db519fd20aa286a2700234d9cdba5945cbdef608fc4075e5a1d64318311144788e4cca8c82c2ed7008389a9bc752e1848dcdd9017856d3a959ff950f7c50ae16d83fb75f9b3f575fe6ed3de0dbb61686a22c0e76ed867529a49ba92c6c0e23f49961bcfcda986bb51262ef40d672bad0e7e680d7bb194cf88ac8f74d3d3acd62a2cb2f49df6013ab04b9e909263e70a7af99dc346d7710d52914daafac46f994399e60dd3d700495fb37d3cab5c6a5e4ba644c4b27c8ba6312f12118bn;
    //private g = 0x992c886130c9f37e7dd70ef072fc4c9cc14cfcfdcb439f1213137071411738605ef64509ccd7fd6aee2cc6bd5be1e7a823b2eea0fa64e76527df4db135f9b97eb333370a7afbd66c5233f925075d2660a1a000052263c0179bf071705faac01c7992af44993702fd144ce9af31913a36d887321511070545b37e43b6b79e1ead0496fd9c7bcc97fcb5d006bf96ff7181ac3da8cece374d208fd67ba5fbcd275dac6f1a84dad662941baa3a3405fa076c846ab1b86e040bed164a6af764214c0449505e7fd2877c167a7336109193b242be5a876649e136b352e83840b57eb99bb5d7a8393aa7f59a2f20e1727fe1cb18166519f381267508f3169388671207ead0cfff375c302f95df675e100b9921bcba60129bde94d559c11cc92e6cdf288edc682fc70f91f7447f2fa390a885cd67482e2531ead69031758234440fac3167624438fd542a2e4f5eb2748f75d1341b349fb2396f1d3ff79d10bcfb14b664d10178dab939579256d4ce81fdc63d7dec3da0ff302f19a8930070491b7b9aae63e896ce566d76de9980dea92943291ff5e34ecb711a0ca7e3d20531475a04925ebc59080554a8acaefc6d87fab0075b45a7be1443910a639f239a21502a2f07f8a58d9cf58253c6acb2594ee448e6e6c83369f29a1cf6ab6bfb92bdc6f13aad01dfe912b21a859f3335f8524d62ebd75341e69c9740cd1e7d27919aee585aaa4d8fcfb03d4fa7b27cb8c1e10895979bb12fbda689aa56b9a4144bc4514dbc27ebe6e0ef1950540f88511c320e00d59bf43fbf5ef42d25c8395438eb6243a3e05d466d8f2b26f67b4ac761ab6c3f4d72795025946d972fbe3faa85999d05f39ba7c447109cfb5d8c1e8613b32c9962086254814ad299381a6678cdbd080bd4061d1c1a2d4d2c5f9d32962a1b30a095e5ff5da900804edcf5890dc40affcc1f5e16a99ace949958f278402bb724c6f60224fab9df4a5cb9e7a554ee023c2c563ec21001bf30e14fc61bf4c43ba9b1d849389352917e4f6f84d24a0daae7742bf24bfcb849c0776e6854a6d0dfa065564985bf407a5e13ce337d82e10f0776b5f6c7717b92c1fa4b32660dac4808a5aa1e7723e3b343e19f0e62b3e1ab45a4dd4019505b200499a3d991396a190a45125327cb596d38dc96f8b151340351f62fbfdb4ae06225f2f73b2e2fed38b0b88db6d4afd2719c9938284ca27f4f0fa5713da1cd0ecd694f610361cee2ef1b98044d9f1aa214053d2f794baedceae10ca62138894d6de454741306773cbc98701048fb31ffae443027da0ff9a99cb0510d0f9043908a98a72e7d8f9a6ccc5b109de972a24d7cb3db780b91d8c9827d9d811f462ff289f012476d1dfbd98999fe32f5e0fb9a8ef11dedb1b6dfe765af3bb0dd70dffc02f440e8a4933e63080af3228b41883efff40f505677561bc6783caa6fcn;
    // DSA Parameters (p=8192bit, q=4096bit)
    p = 0x9d27d809cb5b6190dc3180f4044a932b0ad82c745ece5fc4738d66639c55dcc80914b0ba8e2246770ceee08b0e53d31de10e964c476c3f9c7af0e882fa91c118eb78c0e9dfc2dc73546cea867e37977a3cf557706670122ad4f23bacb286e822adf3dec7e2f71db9ed6044c2cb1cc984f07f768904095a4897d993f32138b1c7bdc3acd1e008ab2ce65eadc618fdb89e38d907660361e2d49221d039d7f3d2fa2268b16c80ed762df4cab78c51e5b4e39375cd4069eeccd40dfa80fc80ad389b59e929c6a1268b9d00f8513dd9b02aa615a0aaff4515043502e68c4dfb82cfe9b2758b4ba6c487dcb1a331c1ab2cbb3c6b55220349a42246ebd80928aa1245749342355cc2580faf3dac9b8bd028eb90b5d2edcde6d14674378a7f89f6ff06e576d1a0d9bfb3bd626d0e582bc0c20bbb29e91eabb7ca90164159997e0dd1040ee22c3edc5e98364928bac9b859edf86a1068532898554b4800c4baa8ad31edffc0c2dd4a3d110d5b079ea9624ee816fdd5226c800aea2370582c780cf9b0444a3f8e5ae50d191a6a363b1fefabf3a833ca147d46a8b40cc3cb4f01fd898036703fa972680be15543f1d9bb97b79be7ccc26117139c838bf29f8617d3f3ed302e092cd0c19d89e57e71f03bd12ed7381b655581c67a6c5274dfb82d0dd1f4eb0c728b6deb724f1a811ebd2a0c9d10cf2d3dc0e5af3519c95ceed1fdf331b9aabdc81a34fdf62a4532e296fd42725efb3626117b85322787c34855b3c81cfe7901ed8d3343238245b61c69e98608e05947e1d6c69918959eb668274f9444bdb0097bb605e546bb71b4785c486dd400424911c7f0788a11533a330df48fe598ab46beb251a13401077562304f8efbb75c7fc84af066a7a5c7cfaf76aa2638b3c75dc75a9b4899d7a7cf36e36741df98f6075b02294f59823faea3a175171abbe48e0fde82bb630a98fce39dc32cc380597781fbc9086c58a2476b2a6bd1f0274a1e47f3413de224ce12a3583bb3cc782b935fef737b04cc6f3109e5f8a7ef8553d6dbe2fc00cbbb107afc868dc726cb20fc93ac7f76058b976337cd61ad6c4aa3afef07120fa36dc44c85bcf3d7dae98fe585f05572c8a220f3cf929ac34e20e204c27b9e2d6118c4b788fdbfc2dbcac5b6b362b85120f62f9abda26b3fe5d28685093477fefcba8501caddeec5c46489d91f92bdfd8e6c9e5d7c1cdd7948509d4f577e14572448d1e4a3fc172b684bd0926340429bcbcbc0d8e79a2c3a4d0f1eb96f5e20c65bce9fe9dbf59ad0879a50b94b00d35a60c2f19c350d48391607fada1c446e24dc869a5670bd8907d6b1f224fbf40546e12f72fcfe253941f9208a65b090d423d4547de1f75e88502de3e631ca74b738477c2b65640ba7c314bb0acdde0bc25702792396336567a0824f99fce1edc02d08983515f1c1e65e00626fffn;
    q = 0xeb8e86973b5bf4cbfe01f68fe7e14856156ba437cc439d64acb8554375d4b65ccd75af4a0beeca75be3554c0e46a7117d4b2fe2eebd5698fc5c797ef41a5e79f384447b13726cf101f99028500adddd36f44d54ed341a0e091b235efed1d35ed53f45dd709d5f96a502c2336f6a0b1ae8098b076a3eeee373abd8ac2d2c0c05377e7efa41da1f471273ee7407d7acdaff5c8a98cbed4e6ef095fba25883beb0a7ad72e70d462722b8b6c59ef8ac1f6c3048eda8de1d7216efa059efb993c54ea67387484f35bddf5b7f6044298dce6497ed3ff10f9bfbccd5422754f805e795e3b145c05158c819a895256c9a3289d469a5c170f2385aef93809372ec6c855cbf9551bdc8a75c230bc2ce901d91de8ab5856d1035cfb8235c3b7a751bb30b630900bd5811bc9e07950575a2ec8c6004c5da9e294924588395985c9660a80b2c08c5c43425812d7bce91b44ec4dd954e1369b24a08f6810ae8cef53228d126949668d740715677613bb119f6a83b9f5173dccf14ed9c49a8f457f9e0825afcd737b5f7b213837e9372c13c9e244527c1b3f964cf76c0a0718e8324f52aba8892d54046fc348270269e2047cfb42a9280077b0a64722780379787c881d3bcac6fc9dfd393aae23e9a56ec8c3f073a45a6a3e48d7d46ff5b75e1034b2d3b860200161618a2dab98622f2c874c55e1d9dcb0f1a3baa0d934d207aa26e892f96fc573n;
    g = 0x3b34a1573743d1224184e496262556e4f82527a6ea42858246a71d169eab92aebd9d23096f910d46158f0043a8afab83b133685dabead0e9d96ec563baa8a795f3861b2c22d6a6fb0212ff3f10b06fa07cd2fbacbe0f646d23c6b3189540388327d6e68553aaca9ccfe0e7e1c40758107c17f2f7d080a5edb0c475c27c2e8b8e8aa5a6a21d69177e871bfbb6ec90cb201fca126f59a9ba48d3ded98c8c8b72f6b3dae93dc01335c73d326ea55d2910892845b32a3f4bbf7e6f6ff2590509f3744dbd3117c63ace3d72fadf7c270006e086b2c8a4a93e942770391f302cc9e3bad2fe2d6d90701ad0dcc8a7f564377a856d76b166e9d973679398d1e64f0183557cfec9f908206e32ccadc9a1a96617329ce7e61aa59e27ccc4382f4fbe95a85ae66ce553227c738d62f174539ee486773157c962c62e86cd1201ff56182b16183b531d9a3dfda3b46aadb1c04acf665ed794229bc64b33af3be661068195a7929f3e1c3bb44c7fb899ced24ec57a7a4a47ede6a61a9c1e84b03acca0abccaa240e3561569b64f00e5e78f0135fa892383cbda1e4f6d6c6b9f845c3b96b55e6fa717cab7c7bd54952eab3249ac706293ad7fe159a2d2e504c090d5f0a7ed360002280efc76b9b7fe57ba5272037b3eb863906b780c1e33ea5b862d78bb8cfe5b317bf4beff6c65b972bb2785d7c45978e332cf0a89b38df695f13ce70158f902ed1eebd92e5b5b42f9a41d45fe4038c11980c4af229287fb858aedcc78853c3d37ef14e8808006cb246f0c76a66823147c9a28aeb42ea6fa0ef7f42566193cf2e78f9d677f8afbfa68b808f0764ef7702be1df1542efbbf37d3b15145893f315291adb3d2809f4ef6443f645a22c7d26cb8168ac310740872a5b41c1c63b3e7c275a37ceb6944928114de84baaf0f7aa98814c77c2be7f2f421a7e1b726ad6b9b9d6b5e0011699be77d2cdf0ae8b4932b0277a463023178b453a53142d298050c4232f0c76fe147ed62c6e507754afa0dc1c16368410c195139f62a0b02774a68054b161e6741b0fb073d3ab75d2a659fdd670378274d38929dcbe66108e3f415b7987cfa4e4b49e8014d1e850c664767cc8482f04c0b39075ff4289696ebec402902008253c34ddbad0f8e25e20224e63369f5db02e5f45ecf285b085678ee1e0e59b2bd0a058a3d2075e928adad29ed537f7b870026e542c85e1b5bbe48e60ba3a62efcbbf9623ce308b8942871fb7cf0da4a263be7c92d96436ffb90cf4ea8edc9543b8de442ef925eb7e01ac81ca14ff886066cd3980fb08b26e3cfec7528129002a216527dc892687a951c3beb851a0c20fc392d77efe68084b843104ec749679c7af382c2fc001cf0767cd005868ee4f8732d73547630af17fe3d35790c1f7bbd2db23159aaf7f719c9bdc0a770da8a20ac812b7c9c7f4f9841f5b111fen;
    pCtx;
    qCtx;
    gTable;
    constructor() {
        this.pCtx = this.makeMontContext(this.p);
        this.qCtx = this.makeMontContext(this.q);
        this.gTable = this.precomputeTable(this.g, this.p, this.pCtx);
    }
    sha256(data) {
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
        const rotr = (x, n) => (x >>> n) | (x << (32 - n));
        let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
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
            let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
            for (let t = 0; t < 64; t++) {
                const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                const ch = (e & f) ^ (~e & g);
                const temp1 = (((h + S1) | 0) + (ch | 0) + (K[t] | 0) + (W[t] | 0)) >>> 0;
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
    inv(e, mod) {
        let r0 = mod, r1 = e;
        let x0 = 0n, x1 = 1n;
        r1 = r1 % mod;
        if (r1 === 0n)
            return 0n;
        while (r1 !== 0n) {
            const q = r0 / r1;
            const r = r0 % r1;
            r0 = r1;
            r1 = r;
            const tmp = x0 - q * x1;
            x0 = x1;
            x1 = tmp;
        }
        if (r0 !== 1n)
            return 0n;
        return x0 < 0n ? x0 + mod : x0;
    }
    bitLength(n) {
        if (n === 0n)
            return 0;
        return n.toString(2).length;
    }
    modPow(base, exp, mod) {
        if (mod === this.p) {
            if (base === this.g) {
                return this.montPowWithTable(this.gTable, exp, this.p, this.pCtx);
            }
            return this.montPow(base, exp, this.p, this.pCtx);
        }
        if (mod === this.q) {
            return this.montPow(base, exp, this.q, this.qCtx);
        }
        const ctx = this.makeMontContext(mod);
        return this.montPow(base, exp, mod, ctx);
    }
    makeMontContext(mod) {
        const bits = this.bitLength(mod);
        const modBits = BigInt(bits);
        const R = 1n << modBits;
        const mask = R - 1n;
        const k = bits > 8192 ? 9 : bits > 4096 ? 8 : bits > 2048 ? 7 : bits > 1024 ? 6 : 5;
        let t = 0n, newT = 1n, r = R, m = mod;
        while (m !== 0n) {
            const q = r / m;
            [t, newT] = [newT, t - q * newT];
            [r, m] = [m, r - q * m];
        }
        const nPrime = (R - (t < 0n ? t + R : t)) & mask;
        return { modBits, R, mask, nPrime, k };
    }
    montReduce(T, mod, ctx) {
        const u = ((T & ctx.mask) * ctx.nPrime) & ctx.mask;
        const x = (T + u * mod) >> ctx.modBits;
        return x >= mod ? x - mod : x;
    }
    precomputeTable(base, mod, ctx) {
        const tableSize = 1 << (ctx.k - 1);
        const table = new Array(tableSize);
        const baseBar = (base << ctx.modBits) % mod;
        const baseBar2 = this.montReduce(baseBar * baseBar, mod, ctx);
        table[0] = baseBar;
        for (let i = 1; i < tableSize; i++) {
            table[i] = this.montReduce(table[i - 1] * baseBar2, mod, ctx);
        }
        return table;
    }
    montPowWithTable(table, exp, mod, ctx) {
        let res = (1n << ctx.modBits) % mod;
        let bitPos = this.bitLength(exp) - 1;
        while (bitPos >= 0) {
            const bit = (exp >> BigInt(bitPos)) & 1n;
            if (!bit) {
                res = this.montReduce(res * res, mod, ctx);
                bitPos--;
            }
            else {
                let winSize = 1, winVal = 1n;
                const maxWinSize = Math.min(ctx.k, bitPos + 1);
                for (let j = 1; j < maxWinSize; j++) {
                    winVal = (winVal << 1n) | ((exp >> BigInt(bitPos - j)) & 1n);
                    winSize = j + 1;
                }
                while (winSize > 1 && !(winVal & 1n)) {
                    winVal >>= 1n;
                    winSize--;
                }
                for (let s = 0; s < winSize; s++)
                    res = this.montReduce(res * res, mod, ctx);
                res = this.montReduce(res * table[Number(winVal >> 1n)], mod, ctx);
                bitPos -= winSize;
            }
        }
        return this.montReduce(res, mod, ctx);
    }
    montPow(base, exp, mod, ctx) {
        const table = this.precomputeTable(base, mod, ctx);
        return this.montPowWithTable(table, exp, mod, ctx);
    }
    BigintToBytes(n, byteLength = 32) {
        const hex = n.toString(16).toUpperCase().padStart(byteLength * 2, "0");
        const bytes = new Uint8Array(byteLength);
        for (let i = 0; i < byteLength; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
    bytesToBigInt(bytes) {
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
    getkeypair() {
        const qLen = Math.ceil(this.q.toString(2).length / 8);
        const pLen = Math.ceil(this.p.toString(2).length / 8);
        const x = globalThis.crypto.getRandomValues(new Uint8Array(qLen));
        const xBigInt = this.bytesToBigInt(x) % (this.q - 1n) + 1n;
        const yBigInt = this.modPow(this.g, xBigInt, this.p);
        return {
            privatekey: this.BigintToBytes(xBigInt, qLen),
            publickey: this.BigintToBytes(yBigInt, pLen)
        };
    }
    sign(message, privateKey) {
        const qLen = Math.ceil(this.q.toString(2).length / 8);
        const x = this.bytesToBigInt(privateKey);
        const k = this.generateK(message, privateKey);
        const r = this.modPow(this.g, k, this.p) % this.q;
        const kInv = this.inv(k, this.q);
        const hash = this.bytesToBigInt(this.sha256(message));
        // % this.q を追加
        const s = (kInv * ((hash + r * x) % this.q)) % this.q;
        if (r === 0n || s === 0n)
            throw new Error("invalid signature, retry");
        const sig = new Uint8Array(qLen * 2);
        sig.set(this.BigintToBytes(r, qLen), 0);
        sig.set(this.BigintToBytes(s, qLen), qLen);
        return sig;
    }
    verify(message, signature, publicKey) {
        const qLen = Math.ceil(this.q.toString(2).length / 8);
        const y = this.bytesToBigInt(publicKey);
        const r = this.bytesToBigInt(signature.slice(0, qLen));
        const s = this.bytesToBigInt(signature.slice(qLen, qLen * 2));
        if (r <= 0n || r >= this.q || s <= 0n || s >= this.q)
            return false;
        const w = this.inv(s, this.q);
        const hash = this.bytesToBigInt(this.sha256(message));
        const u1 = (hash * w) % this.q;
        const u2 = (r * w) % this.q;
        const v = ((this.modPow(this.g, u1, this.p) * this.modPow(y, u2, this.p)) % this.p) % this.q;
        return v === r;
    }
    bigintToHex(n, byteLength) {
        const hex = n.toString(16).toUpperCase();
        const padLen = byteLength ? byteLength * 2 : hex.length + (hex.length % 2);
        return hex.padStart(padLen, "0");
    }
    hexToBigInt(hex) {
        return BigInt("0x" + hex);
    }
    generateK(message, privateKey) {
        const qLen = Math.ceil(this.q.toString(2).length / 8);
        // ステップa: h1 = hash(message)
        const h1 = this.sha256(message);
        // ステップb: V = 0x01 * 32
        let V = new Uint8Array(qLen).fill(0x01);
        // ステップc: K = 0x00 * 32
        let K = new Uint8Array(qLen).fill(0x00);
        // ステップd: K = HMAC-SHA256(K, V || 0x00 || privateKey || h1)
        K = this.hmacSha256(K, new Uint8Array([...V, 0x00, ...privateKey, ...h1]));
        // ステップe: V = HMAC-SHA256(K, V)
        V = this.hmacSha256(K, V);
        // ステップf: K = HMAC-SHA256(K, V || 0x01 || privateKey || h1)
        K = this.hmacSha256(K, new Uint8Array([...V, 0x01, ...privateKey, ...h1]));
        // ステップg: V = HMAC-SHA256(K, V)
        V = this.hmacSha256(K, V);
        // ステップh: 候補を生成してqの範囲に収まるまで繰り返す
        while (true) {
            // T を空にする
            let T = new Uint8Array(0);
            // T が qLen 以上になるまで V を追加
            while (T.length < qLen) {
                V = this.hmacSha256(K, V);
                T = new Uint8Array([...T, ...V]);
            }
            // k候補を取り出す
            const k = this.bytesToBigInt(T.slice(0, qLen));
            // 1 <= k <= q-1 なら採用
            if (k >= 1n && k < this.q) {
                return k;
            }
            // 範囲外なら K, V を更新して再試行
            K = this.hmacSha256(K, new Uint8Array([...V, 0x00]));
            V = this.hmacSha256(K, V);
        }
    }
    hmacSha256(key, data) {
        const BLOCK = 64;
        const k = key.length > BLOCK ? this.sha256(key) : key;
        const kPadded = new Uint8Array(BLOCK);
        kPadded.set(k);
        const ipad = kPadded.map((b) => b ^ 0x36);
        const opad = kPadded.map((b) => b ^ 0x5c);
        return this.sha256(this.concat(opad, this.sha256(this.concat(ipad, data))));
    }
    concat(...arrays) {
        const total = arrays.reduce((n, a) => n + a.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const a of arrays) {
            out.set(a, offset);
            offset += a.length;
        }
        return out;
    }
    bytesToHex(bytes) {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }
    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
    getKeypairhex() {
        const { privatekey, publickey } = this.getkeypair();
        return {
            privatekey: this.bigintToHex(this.bytesToBigInt(privatekey)),
            publickey: this.bigintToHex(this.bytesToBigInt(publickey))
        };
    }
    signhex(message, privateKey) {
        const privateKeyBytes = this.hexToBytes(privateKey);
        const signature = this.sign(message, privateKeyBytes);
        return this.bytesToHex(signature);
    }
    verifyhex(message, signatureHex, publicKeyHex) {
        const signatureBytes = this.hexToBytes(signatureHex);
        const publicKeyBytes = this.hexToBytes(publicKeyHex);
        return this.verify(message, signatureBytes, publicKeyBytes);
    }
    privatekeytopublickey(privateKeyHex) {
        const privateKeyBytes = this.hexToBytes(privateKeyHex);
        const xBigInt = this.bytesToBigInt(privateKeyBytes);
        const yBigInt = this.modPow(this.g, xBigInt, this.p);
        return this.bigintToHex(yBigInt);
    }
    dh(privateKeyHex, publicKeyHex) {
        const privateKeyBytes = this.hexToBytes(privateKeyHex);
        const publicKeyBytes = this.hexToBytes(publicKeyHex);
        const publicKeyBytesbigInt = this.bytesToBigInt(publicKeyBytes);
        if (publicKeyBytesbigInt <= 0n || publicKeyBytesbigInt >= this.p || this.modPow(publicKeyBytesbigInt, this.q, this.p) !== 1n) {
            throw new Error("Invalid public key");
        }
        const xBigInt = this.bytesToBigInt(privateKeyBytes);
        const yBigInt = this.bytesToBigInt(publicKeyBytes);
        const sharedSecret = this.modPow(yBigInt, xBigInt, this.p);
        return this.sha256(this.BigintToBytes(sharedSecret));
    }
}
// 使用例
const dsaInstance = new dsa();
const ciphers = new cipher();
const encoder = new TextEncoder();
const message = encoder.encode("Hello, World!");
const key = new Uint8Array(32); // 256-bit key
globalThis.crypto.getRandomValues(key);
console.time("encryption");
const encrypted = ciphers.encrypt(message, key);
console.timeEnd("encryption");
console.log("Encrypted:", dsaInstance.bytesToHex(encrypted));
console.time("decryption");
const decrypted = ciphers.decrypt(encrypted, key);
console.timeEnd("decryption");
if (decrypted) {
    const decoder = new TextDecoder();
    console.log("Decrypted:", decoder.decode(decrypted));
}
console.time("DSA Key Generation");
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
console.log("alice bob key exchange:");
const alice = dsaInstance.getKeypairhex();
const bob = dsaInstance.getKeypairhex();
console.log("Alice Public Key:", alice.publickey);
console.log("Bob Public Key:", bob.publickey);
console.log("Alice private Key:", alice.privatekey);
console.log("Bob private Key:", bob.privatekey);
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
    const el = (tag, cls = "", text = "") => {
        const e = document.createElement(tag);
        if (cls)
            e.className = cls;
        if (text)
            e.textContent = text;
        return e;
    };
    const addField = (parent, labelText, child) => {
        const f = el("div", "ct-field");
        f.appendChild(el("label", "ct-label", labelText));
        f.appendChild(child);
        parent.appendChild(f);
        return child;
    };
    const addOutput = (parent, labelText) => {
        const f = el("div", "ct-field");
        f.appendChild(el("label", "ct-label", labelText));
        const wrap = el("div", "ct-output-wrap");
        const out = el("div", "ct-output");
        out.textContent = "—";
        const copy = el("button", "ct-copy", "copy");
        copy.addEventListener("click", () => {
            if (out.textContent === "—")
                return;
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
    const addBtn = (parent, text, onClick) => {
        const f = el("div", "ct-field");
        const b = el("button", "ct-btn", text);
        b.addEventListener("click", onClick);
        f.appendChild(b);
        parent.appendChild(f);
        return b;
    };
    const mkTextarea = (placeholder = "") => {
        const t = el("textarea", "ct-textarea");
        t.placeholder = placeholder;
        return t;
    };
    const mkInput = (placeholder = "") => {
        const i = el("input", "ct-input");
        i.type = "text";
        i.placeholder = placeholder;
        return i;
    };
    // ── ヘッダー ──
    const header = el("div");
    header.id = "ct-header";
    header.innerHTML = `<h1>DSAとAESもどき</h1><p>eccがすでにあるのに...</p>`;
    document.body.appendChild(header);
    // ── タブバー ──
    const tabBar = el("div");
    tabBar.id = "ct-tabs";
    document.body.appendChild(tabBar);
    // ── パネル ──
    const panelContainer = el("div");
    panelContainer.id = "ct-panels";
    document.body.appendChild(panelContainer);
    const tabs = [];
    const panelEls = [];
    const addTab = (name, build) => {
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
            }
            catch (e) {
                out.textContent = "エラー: " + e.message;
            }
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
            }
            catch (e) {
                out.textContent = "エラー: " + e.message;
            }
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
            }
            catch (e) {
                out.textContent = "エラー: " + e.message;
            }
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
            }
            catch (e) {
                out.textContent = "エラー: " + e.message;
            }
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
            }
            catch (e) {
                badge.innerHTML = `<span class="ct-badge invalid">エラー: ${e.message}</span>`;
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
        const pubIn = mkInput("相手の公開鍵 (hex)");
        addField(p, "peer public key (hex)", pubIn);
        const out = addOutput(p, "shared secret (hex)");
        addBtn(p, "共有秘密を導出する", () => {
            try {
                out.textContent = dsaInst.bytesToHex(dsaInst.dh(privIn.value.trim(), pubIn.value.trim()));
            }
            catch (e) {
                out.textContent = "エラー: " + e.message;
            }
        });
    });
    // 最初のタブをアクティブに
    tabs[0]?.classList.add("active");
    panelEls[0]?.classList.add("active");
})();
