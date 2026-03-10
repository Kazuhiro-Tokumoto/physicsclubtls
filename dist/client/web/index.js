import { p_256 } from "./module/p-256.js";
import { AES } from "./module/aes.js";
const test = async () => {
    const aes = new AES();
    const p256 = new p_256();
    const alice = await p256.generateKeyPair();
    console.log("Aliceの公開鍵:", alice.publicKey);
    console.log("Aliceの秘密鍵:", alice.privateKey);
    const bob = await p256.generateKeyPair();
    console.log("Bobの公開鍵:", bob.publicKey);
    console.log("Bobの秘密鍵:", bob.privateKey);
    const secret1 = await p256.ecdh(alice.privateKey, bob.publicKey);
    console.log("Aliceが計算した共有秘密:", secret1);
    const secret2 = await p256.ecdh(bob.privateKey, alice.publicKey);
    console.log("Bobが計算した共有秘密:", secret2);
    const match = secret1 === secret2;
    console.log("一致:", match);
    const encoder = new TextEncoder();
    const key = p256.sha256(encoder.encode(secret1));
    const plaintext = encoder.encode("Hello, TLS!");
    const ciphertext = await aes.encrypt(plaintext, key);
    console.log("暗号文:", ciphertext);
    const decrypted = await aes.decrypt(ciphertext, key);
    const decoder = new TextDecoder();
    console.log("復号文:", decoder.decode(decrypted));
};
const rootkey = [
    "030FB3C4DA03E4E495C56368E3C55F7846A295E1C6DA14954F8379C82586135B08",
    "02D14FC65E11D39903C95371BEDDE5556555BDF28FA66648A4B8630B2E327A6A11",
    "0305EE86431958420A4003E680A94427CD4654514477331A8566F0C055ADB2482C",
];
const test2 = async () => {
    const p256 = new p_256();
    for (const key of rootkey) {
        const pubraw = p256.decompressPublicKey(key);
        const slice1 = pubraw.slice(0, 64);
        const slice2 = pubraw.slice(64);
        const slice1tobigint = BigInt("0x" + slice1);
        const slice2tobigint = BigInt("0x" + slice2);
        const pubrawbigint = [slice1tobigint, slice2tobigint];
        const pub = await p256.isPointOnCurve(pubrawbigint);
        console.log(`公開鍵 ${key} は楕円曲線上にあります:`, pub);
    }
};
function canonicalJSON(obj) {
    if (typeof obj !== "object" || obj === null)
        return JSON.stringify(obj);
    if (Array.isArray(obj))
        return "[" + obj.map(canonicalJSON).join(",") + "]";
    const record = obj;
    const keys = Object.keys(record).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${canonicalJSON(record[k])}`);
    return "{" + pairs.join(",") + "}";
}
// チェーンが正しいかだけ
const verifyCertificate = (cert) => {
    const p256 = new p_256();
    const encoder = new TextEncoder();
    const verifyCAChain = (cas, parentPubkey) => {
        for (const ca of cas) {
            const valid = p256.verify(encoder.encode(ca.publickey), ca.signature, parentPubkey);
            if (!valid)
                return false;
            if (ca.end || ca.domain)
                continue; // ← ここだけ変更
            if (ca.CA && ca.CA.length > 0) {
                if (!verifyCAChain(ca.CA, ca.publickey))
                    return false;
            }
        }
        return true;
    };
    for (const root of cert.root) {
        const rootPubkey = rootkey[root.keynumber];
        if (!rootPubkey)
            return false;
        for (const ca of root.CA) {
            const valid = p256.verify(encoder.encode(ca.publickey), root.sign, rootPubkey);
            if (!valid)
                return false;
        }
        for (const ca of root.CA) {
            if (ca.end)
                continue;
            if (ca.CA && ca.CA.length > 0) {
                if (!verifyCAChain(ca.CA, ca.publickey))
                    return false;
            }
        }
    }
    return true;
};
// ドメインが存在するか＋署名から3ヶ月以内か
const verifyDomain = (cert, targetDomain) => {
    const p256 = new p_256();
    const encoder = new TextEncoder();
    const now = Date.now();
    const threeMonths = 90 * 24 * 60 * 60 * 1000;
    const searchCAs = (cas) => {
        for (const ca of cas) {
            if (ca.domain) {
                for (const domain of ca.domain) {
                    if (domain.domainname !== targetDomain)
                        continue;
                    const signDate = new Date(domain.signday).getTime();
                    if (now - signDate > threeMonths)
                        return false;
                    return p256.verify(encoder.encode(canonicalJSON(domain)), ca.signature, ca.publickey);
                }
            }
            if (ca.CA) {
                if (searchCAs(ca.CA))
                    return true;
            }
        }
        return false;
    };
    for (const root of cert.root) {
        if (searchCAs(root.CA))
            return true;
    }
    return false;
};
const test4 = async () => {
    const p256test = new p_256();
    const encoder = new TextEncoder();
    const rootKP = p256test.generateKeyPair();
    const caKP = p256test.generateKeyPair();
    const rootSign = p256test.sign(encoder.encode(caKP.publicKey), rootKP.privateKey);
    // CAテスト: チェーンのみ
    const certCA = {
        root: [
            {
                keynumber: 0,
                sign: "CB4FB7C5DD2067E0E6C94029B72DF8ECC53C3F542C3C5CF3FF8B6273BA7B906F2CF83DDE96325BC926E78F16F9A194BC4EEA445BA2483254186F0FB9E9561DB8",
                nameca: "CA仮",
                CA: [],
            },
        ],
    };
    const originalRootKey = rootkey[0];
    rootkey[0] = rootKP.publicKey;
    console.log("チェーン検証:", verifyCertificate(certCA), "← trueが正解");
    // Domainテスト: ドメイン名とチェーン
    const certDomain = {
        root: [
            {
                keynumber: 0,
                sign: "CB4FB7C5DD2067E0E6C94029B72DF8ECC53C3F542C3C5CF3FF8B6273BA7B906F2CF83DDE96325BC926E78F16F9A194BC4EEA445BA2483254186F0FB9E9561DB8",
                nameca: "CA仮",
                CA: [
                    {
                        publickey: "030FB3C4DA03E4E495C56368E3C55F7846A295E1C6DA14954F8379C82586135B08",
                        caname: "",
                        signature: "4C068212AD1D563ED4E6C1B9A06AE1351F47E480047BDF8502A51D277F3F94ADB5774F8D3623F1545871ABF34CAC868648CA50194216021F00FA634FEEA23BAC",
                        end: true,
                        domain: [
                            {
                                domainname: "example.com",
                                pubkey: "030FB3C4DA03E4E495C56368E3C55F7846A295E1C6DA14954F8379C82586135B08",
                                signday: "2026-02-28",
                            },
                        ],
                    },
                ],
            },
        ],
    };
    console.log("ドメイン検証 (example.com):", verifyDomain(certDomain, "example.com"), "← trueが正解");
    console.log("ドメイン検証 (other.com):", verifyDomain(certDomain, "other.com"), "← falseが正解");
    rootkey[0] = originalRootKey;
};
const test3 = async () => {
    await test();
    await test2();
    await test4();
};
test3();
