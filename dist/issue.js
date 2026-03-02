// issuer.ts — DYLA Certificate Issuer
// Depends on: ./dist/DYLA.js
import { DYLA } from "./DYLA.js";
import { p_256 } from "./p-256.js";
const ec = new p_256();
function nowISO() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}
// ===== ルートCA鍵ペア生成 =====
// trust storeに埋め込む用。証明書は作らない。
export function generateRootCA() {
    return DYLA.generateKeyPair();
}
// ===== 中間CA発行 =====
// 親CAの秘密鍵で署名。返り値はエントリ単体 + 新しい鍵ペア。
// order: チェーン内の位置（ルートCAから直接なら0、中間CAからなら1, 2, ...）
export function issueIntermediateCA(parentCAName, parentPrivateKey, order, cn, country, state, city, text = "") {
    const keyPair = DYLA.generateKeyPair();
    const domain = {
        CN: cn,
        IsCA: true,
        Pubkey: "04" + ec.decompressPublicKey(keyPair.publicKey),
        Country: country,
        State: state,
        City: city,
        IssuedAt: nowISO()
    };
    const entry = DYLA.createEntry(parentCAName, order, domain, parentPrivateKey, text);
    return { entry, keyPair };
}
// ===== エンドエンティティ証明書発行 =====
// 親CA（ルートでも中間でも可）の秘密鍵で署名。
// chainEntries: 親CAまでのチェーン（Order順）
export function issueEndEntity(parentCAName, parentPrivateKey, chainEntries, cn, country, state, city, text = "") {
    const keyPair = DYLA.generateKeyPair();
    const order = chainEntries.length;
    const domain = {
        CN: cn,
        IsCA: false,
        Pubkey: "04" + ec.decompressPublicKey(keyPair.publicKey),
        Country: country,
        State: state,
        City: city,
        IssuedAt: nowISO()
    };
    const entry = DYLA.createEntry(parentCAName, order, domain, parentPrivateKey, text);
    const cert = new DYLA({ DYLA: [...chainEntries, entry] });
    return { cert, keyPair };
}
// ===== 既存チェーンに中間CAを追加 =====
// 既存の中間CAから更に中間CAを発行
export function issueSubCA(parentEntry, parentPrivateKey, chainEntries, cn, country, state, city, text = "") {
    const order = chainEntries.length;
    const result = issueIntermediateCA(parentEntry.Domain.CN, parentPrivateKey, order, cn, country, state, city, text);
    return {
        entry: result.entry,
        keyPair: result.keyPair,
        chain: [...chainEntries, result.entry]
    };
}
// ===== PEMインポートからの発行 =====
// 既存のDYLA PEM証明書をインポートし、CA秘密鍵で新しい証明書を発行
export function issueFromPEM(pem, caPrivateKey, cn, isCA, country, state, city, text = "") {
    const existing = DYLA.fromPEM(pem);
    const lastEntry = existing.endEntity;
    if (!lastEntry)
        throw new Error("Empty certificate chain");
    if (!lastEntry.Domain.IsCA)
        throw new Error("Last entry is not a CA, cannot issue from it");
    const keyPair = DYLA.generateKeyPair();
    const order = existing.chainLength;
    const domain = {
        CN: cn,
        IsCA: isCA,
        Pubkey: "04" + ec.decompressPublicKey(keyPair.publicKey),
        Country: country,
        State: state,
        City: city,
        IssuedAt: nowISO()
    };
    const entry = DYLA.createEntry(lastEntry.Domain.CN, order, domain, caPrivateKey, text);
    const cert = new DYLA({ DYLA: [...existing.entries, entry] });
    return { cert, keyPair };
}
