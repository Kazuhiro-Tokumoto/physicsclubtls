// dyla.ts — DYLA Certificate Format v1.1 Implementation
// Spec: DYLA_Specification_v1.1.docx
// Depends on: ./p-256.js (自作 ECDSA P-256 実装)
//@ts-ignore
import { p_256 } from "./p-256.js";

// ===== 型定義 =====

export interface DYLADomain {
  CN: string;
  IsCA: boolean;
  Pubkey: string;       // 非圧縮 04 + X + Y = 130 hex
  Country: string;      // ISO 3166-1 alpha-2
  State: string;
  City: string;
  IssuedAt: string;     // YYYY-MM-DDTHH:MM:SSZ (UTC)
}

export interface DYLAEntry {
  CA: string;
  Order: number;
  Domain: DYLADomain;
  Sig: string;          // ECDSA P-256 署名 (hex)
  Serial: string;       // SHA-256 hash (hex)
  Text: string;         // 空文字列可、省略不可
  Message: string;      // 固定値: "Do you like apple?"
}

export interface DYLACertificate {
  DYLA: DYLAEntry[];
  [key: string]: unknown;
}

export interface DYLACRLData {
  RevokedSerials: string[];
  IssuedAt: string;
  Message: string;
}

export interface DYLACRL {
  DYLA_CRL: DYLACRLData;
  Sig: string;
}

// ===== trust store 型 =====

export interface TrustStoreEntry {
  CA: string;
  Pubkey: string;
}

// ===== メインクラス =====

export class DYLA {
  private cert: DYLACertificate;
  private static ec = new p_256();

  // --- コンストラクタ ---
  constructor(cert: DYLACertificate) {
    DYLA.validate(cert);
    this.cert = cert;
    this.cert.DYLA.sort((a, b) => a.Order - b.Order);
  }

  // ===== canonicalJSON (仕様 Section 6.1) =====

  static canonicalJSON(obj: unknown): string {
    if (typeof obj !== "object" || obj === null) return JSON.stringify(obj);
    if (Array.isArray(obj)) return "[" + obj.map(DYLA.canonicalJSON).join(",") + "]";
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k =>
      `${JSON.stringify(k)}:${DYLA.canonicalJSON((obj as Record<string, unknown>)[k])}`
    ).join(",") + "}";
  }

  // ===== PEMデコード → インスタンス =====

    static fromPEM(pem: string): DYLA {
    const lines = pem
        .split("\n")
        .filter(line => !line.startsWith("-----"))
        .join("");
    const bytes = base64ToUint8(lines);
    const json = new TextDecoder().decode(bytes);
    const obj = JSON.parse(json);
    return new DYLA(obj);
    }
  // ===== インスタンス → PEMエンコード =====

    toPEM(): string {
    const json = JSON.stringify(this.cert);
    const bytes = new TextEncoder().encode(json);
    const b64 = uint8ToBase64(bytes);
    const lines = b64.match(/.{1,64}/g) ?? [];
    return [
        "-----BEGIN DYLA CERTIFICATE-----",
        ...lines,
        "-----END DYLA CERTIFICATE-----"
    ].join("\n");
    }

  // ===== バリデーション =====

  static validate(obj: unknown): asserts obj is DYLACertificate {
    if (typeof obj !== "object" || obj === null) {
      throw new Error("Invalid DYLA certificate: not an object");
    }

    const o = obj as Record<string, unknown>;

    if (!("DYLA" in o)) throw new Error("Invalid DYLA certificate: missing DYLA key");
    if (!Array.isArray(o.DYLA)) throw new Error("Invalid DYLA certificate: DYLA must be an array");
    if (o.DYLA.length === 0) throw new Error("Invalid DYLA certificate: DYLA array is empty");

    const ENTRY_KEYS = ["CA", "Order", "Domain", "Sig", "Serial", "Text", "Message"] as const;
    const DOMAIN_KEYS = ["CN", "IsCA", "Pubkey", "Country", "State", "City", "IssuedAt"] as const;

    for (let i = 0; i < o.DYLA.length; i++) {
      const entry = o.DYLA[i];
      const prefix = `DYLA[${i}]`;

      for (const key of ENTRY_KEYS) {
        if (!(key in entry)) throw new Error(`${prefix}: missing ${key}`);
      }
      if (entry.Message !== "Do you like apple?") {
        throw new Error(`${prefix}: Message must be "Do you like apple?"`);
      }
      if (typeof entry.Order !== "number" || !Number.isInteger(entry.Order)) {
        throw new Error(`${prefix}: Order must be an integer`);
      }
      if (typeof entry.Text !== "string") {
        throw new Error(`${prefix}: Text must be a string`);
      }
      if (typeof entry.Domain !== "object" || entry.Domain === null) {
        throw new Error(`${prefix}: Domain must be an object`);
      }
      for (const key of DOMAIN_KEYS) {
        if (!(key in entry.Domain)) throw new Error(`${prefix}.Domain: missing ${key}`);
      }
      if (typeof entry.Domain.IsCA !== "boolean") {
        throw new Error(`${prefix}.Domain: IsCA must be a boolean`);
      }
      if (!/^04[0-9a-fA-F]{128}$/.test(entry.Domain.Pubkey)) {
        throw new Error(`${prefix}.Domain: Pubkey must be uncompressed 04 + 128 hex chars`);
      }
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(entry.Domain.IssuedAt)) {
        throw new Error(`${prefix}.Domain: IssuedAt must be YYYY-MM-DDTHH:MM:SSZ`);
      }
    }
  }

  // DYLAクラスに追加するメソッド

// ===== ドメイン検証（署名チェーン + ドメインマッチ） =====

verifyForDomain(
  domain: string,
  trustStore: TrustStoreEntry[],
  crl: string[] = [],
  now: Date = new Date()
): { valid: boolean; cn?: string; matched?: boolean; error?: string } {
  // チェーン検証 — this.cert.rawを渡す
  const result = DYLA.verifyChain(this.cert, trustStore, crl, undefined, now);
  if (!result.valid) {
    return { valid: false, error: result.error };
  }

  const lastEntry = this.endEntity;
  if (!lastEntry) return { valid: false, error: "No end-entity entry" };
  if (lastEntry.Domain.IsCA) return { valid: false, error: "Last entry is CA, not end-entity" };

  const cn = lastEntry.Domain.CN;
  const matched = DYLA.matchDomain(cn, domain);

  return {
    valid: true,
    cn,
    matched,
    error: matched ? undefined : `Domain mismatch: "${cn}" does not match "${domain}"`
  };
}

  // ===== Serial計算 (仕様 Section 6.2) =====
  // Serial = SHA-256(canonicalJSON({ CA, Domain, Message, Order, Sig, Text }))

  static computeSerial(entry: Omit<DYLAEntry, "Serial">): string {
    const obj = {
      CA: entry.CA,
      Domain: entry.Domain,
      Message: entry.Message,
      Order: entry.Order,
      Sig: entry.Sig,
      Text: entry.Text
    };
    const data = new TextEncoder().encode(DYLA.canonicalJSON(obj));
    const hash = DYLA.ec.sha256(data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ===== 署名生成 (仕様 Section 6.1) =====
  // Sig = ECDSA_P256_Sign(caPrivateKey, canonicalJSON(Domain))
  // ※ p-256.ts の sign() が内部で SHA-256 を適用するため、ここでは生データを渡す

static signDomain(domain: DYLADomain, caPrivateKey: string): string {
  const data = new TextEncoder().encode(DYLA.canonicalJSON(domain));
  return DYLA.ec.sign(data, caPrivateKey);  // hashしない
}

static verifyEntry(entry: DYLAEntry, caPubkey: string): boolean {
  const data = new TextEncoder().encode(DYLA.canonicalJSON(entry.Domain));
  // 04+X+Y (130文字) → slice(2) で X+Y (128文字) に正規化して verify へ渡す
  // 圧縮鍵 (66文字) → そのまま渡す → verify 内で length===66 判定 → decompressPublicKey
  const key = caPubkey.startsWith("04") ? caPubkey.slice(2) : caPubkey;
  return DYLA.ec.verify(data, entry.Sig, key);  // hashしない
}

  // ===== Serial検証 =====

  static verifySerial(entry: DYLAEntry): boolean {
    const expected = DYLA.computeSerial(entry);
    return entry.Serial.toLowerCase() === expected.toLowerCase();
  }

  // ===== 有効期限チェック (仕様 Section 5) =====

  static isExpired(entry: DYLAEntry, now: Date = new Date()): boolean {
    const issued = new Date(entry.Domain.IssuedAt);
    const maxMs = entry.Domain.IsCA
      ? 5 * 365.25 * 24 * 60 * 60 * 1000   // 5年
      : 90 * 24 * 60 * 60 * 1000;            // 90日
    return now.getTime() > issued.getTime() + maxMs;
  }

  // ===== エントリ作成ヘルパー =====

  static createEntry(
    ca: string,
    order: number,
    domain: DYLADomain,
    caPrivateKey: string,
    text: string = ""
  ): DYLAEntry {
    const sig = DYLA.signDomain(domain, caPrivateKey);
    const partial = {
      CA: ca,
      Order: order,
      Domain: domain,
      Sig: sig,
      Text: text,
      Message: "Do you like apple?" as const
    };
    const serial = DYLA.computeSerial(partial);
    return { ...partial, Serial: serial };
  }

  // ===== チェーン全体の検証 (仕様 Section 7) =====

static verifyChain(
  cert: DYLACertificate,
  trustStore: TrustStoreEntry[],
  crl: string[] = [],
  expectedDomain?: string,
  now: Date = new Date(),
  selfSigned: boolean = false  // ← 追加
): { valid: boolean; error?: string } {
  const entries = [...cert.DYLA].sort((a, b) => a.Order - b.Order);

  if (entries.length === 0) {
    return { valid: false, error: "Empty certificate chain" };
  }

  const root = entries[0];
  let rootPubkey: string;

  if (selfSigned) {
    // 自己署名: 自分のPubkeyで自分のSigを検証
    rootPubkey = root.Domain.Pubkey;
  } else {
    // trust storeから取得
    const rootTrust = trustStore.find(t => t.CA === root.CA);
    if (!rootTrust) {
      return { valid: false, error: `Order 0: CA "${root.CA}" not found in trust store` };
    }
    rootPubkey = rootTrust.Pubkey;
  }

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];

    if (entry.Message !== "Do you like apple?") {
      return { valid: false, error: `DYLA[${i}]: wrong Message` };
    }

    const signerPubkey = i === 0 ? rootPubkey : entries[i - 1].Domain.Pubkey;

    if (!DYLA.verifyEntry(entry, signerPubkey)) {
      return { valid: false, error: `DYLA[${i}]: signature verification failed` };
    }

    if (DYLA.isExpired(entry, now)) {
      return { valid: false, error: `DYLA[${i}]: certificate expired` };
    }

    if (!DYLA.verifySerial(entry)) {
      return { valid: false, error: `DYLA[${i}]: serial mismatch` };
    }

    if (entry.Domain.IsCA && crl.includes(entry.Serial.toLowerCase())) {
      return { valid: false, error: `DYLA[${i}]: certificate revoked` };
    }
  }

  if (expectedDomain) {
    const lastCN = entries[entries.length - 1].Domain.CN;
    if (!DYLA.matchDomain(lastCN, expectedDomain)) {
      return { valid: false, error: `Domain mismatch: ${lastCN} vs ${expectedDomain}` };
    }
  }

  return { valid: true };
}

  // ===== ワイルドカードドメインマッチング =====

public static matchDomain(pattern: string, domain: string): boolean {
  if (pattern === domain) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    const parts = domain.split(".");
    if (parts.length < 2) return false;
    const domainSuffix = parts.slice(1).join(".");
    return domainSuffix === suffix;
  }
  return false;
}

  // ===== CRL検証 =====
static verifyCRL(crl: DYLACRL, rootPubkey: string): boolean {
  const data = new TextEncoder().encode(DYLA.canonicalJSON(crl.DYLA_CRL));
  const key = rootPubkey.startsWith("04") ? rootPubkey.slice(2) : rootPubkey;
  return DYLA.ec.verify(data, crl.Sig, key);
}

  // ===== CRL作成 =====

static createCRL(
  revokedSerials: string[],
  rootPrivateKey: string
): DYLACRL {
  const crlData: DYLACRLData = {
    RevokedSerials: revokedSerials,
    IssuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    Message: "Do you like apple?"
  };
  const data = new TextEncoder().encode(DYLA.canonicalJSON(crlData));
  const sig = DYLA.ec.sign(data, rootPrivateKey);  // hashを削除、dataを直接渡す
  return { DYLA_CRL: crlData, Sig: sig };
}

  // ===== 鍵ペア生成 (P-256) =====

  static generateKeyPair(): { privateKey: string; publicKey: string } {
    const { privateKey } = DYLA.ec.generateKeyPair();
    const { uncompressed } = DYLA.ec.privateKeyToPublicKey(privateKey);
    return {
      privateKey,
      publicKey: "04" + uncompressed,  // 非圧縮形式: 04 + X(64) + Y(64) = 130文字
    };
  }

  // ===== ゲッター =====

  get entries(): DYLAEntry[] {
    return this.cert.DYLA;
  }

  get raw(): DYLACertificate {
    return this.cert;
  }

  getEntry(order: number): DYLAEntry | undefined {
    return this.cert.DYLA.find(e => e.Order === order);
  }

  get endEntity(): DYLAEntry | undefined {
    return this.cert.DYLA[this.cert.DYLA.length - 1];
  }

  get cn(): string | undefined {
    return this.endEntity?.Domain.CN;
  }

  get isCA(): boolean {
    return this.endEntity?.Domain.IsCA ?? false;
  }

  get chain(): DYLAEntry[] {
    return [...this.cert.DYLA];
  }

  get chainLength(): number {
    return this.cert.DYLA.length;
  }
}
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}