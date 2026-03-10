import * as readline from "readline";
import * as fs from "fs";
import { p_256 } from "./module/p-256.js";

const p256 = new p_256();
const encoder = new TextEncoder();

function canonicalJSON(obj: unknown): string {
  if (typeof obj !== "object" || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJSON).join(",") + "]";
  const record = obj as Record<string, unknown>;
  const keys: string[] = Object.keys(record).sort();
  const pairs: string[] = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJSON(record[k])}`,
  );
  return "{" + pairs.join(",") + "}";
}

export type DomainEntry = {
  domainname: string;
  pubkey: string;
  signday: string;
};

export type CAEntry = {
  publickey: string;
  caname: string;
  signature: string;
  end?: boolean;
  domain?: DomainEntry[];
  CA?: CAEntry[];
};

export type RootEntry = {
  keynumber: number;
  sign: string;
  nameca: string;
  CA: CAEntry[];
};

export type Certificate = {
  root: RootEntry[];
};

// ===== 検証ロジック =====

const rootkeys: string[] = [
  "030FB3C4DA03E4E495C56368E3C55F7846A295E1C6DA14954F8379C82586135B08",
  "02D14FC65E11D39903C95371BEDDE5556555BDF28FA66648A4B8630B2E327A6A11",
  "0305EE86431958420A4003E680A94427CD4654514477331A8566F0C055ADB2482C",
];

function verifyCAChain(cas: CAEntry[], parentPubkey: string): boolean {
  for (const ca of cas) {
    const valid = p256.verify(
      encoder.encode(ca.publickey),
      ca.signature,
      parentPubkey,
    );
    if (!valid) return false;

    if (ca.end || ca.domain) continue;

    if (ca.CA && ca.CA.length > 0) {
      if (!verifyCAChain(ca.CA, ca.publickey)) return false;
    }
  }
  return true;
}

export function verifyCertificate(
  cert: Certificate,
  targetDomain?: string,
): boolean {
  for (const root of cert.root) {
    const rootPubkey = rootkeys[root.keynumber];
    if (!rootPubkey) return false;

    for (const ca of root.CA) {
      const valid = p256.verify(
        encoder.encode(ca.publickey),
        root.sign,
        rootPubkey,
      );
      if (!valid) return false;

      if (ca.end || ca.domain) continue;

      if (ca.CA && ca.CA.length > 0) {
        if (!verifyCAChain(ca.CA, ca.publickey)) return false;
      }
    }
  }

  if (targetDomain) {
    return findDomain(cert, targetDomain);
  }
  return true;
}

function findDomain(cert: Certificate, targetDomain: string): boolean {
  const searchCAs = (cas: CAEntry[]): boolean => {
    for (const ca of cas) {
      if (ca.domain?.some((d) => d.domainname === targetDomain)) return true;
      if (ca.CA) {
        if (searchCAs(ca.CA)) return true;
      }
    }
    return false;
  };
  for (const root of cert.root) {
    if (searchCAs(root.CA)) return true;
  }
  return false;
}

// ===== CLIツール =====

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const question = (prompt: string): Promise<string> =>
  new Promise((resolve) => rl.question(prompt, resolve));

function listCAs(
  cas: CAEntry[],
  prefix: string = "",
  results: { path: number[]; ca: CAEntry }[] = [],
  currentPath: number[] = [],
): { path: number[]; ca: CAEntry }[] {
  cas.forEach((ca, i) => {
    const path = [...currentPath, i];
    const endMark = ca.end ? " [END]" : ca.domain ? " [DOMAIN]" : "";
    console.log(
      `  [${results.length}] ${prefix}${ca.caname} (${ca.publickey.slice(0, 16)}...)${endMark}`,
    );
    results.push({ path, ca });
    if (ca.CA) listCAs(ca.CA, prefix + "  ", results, path);
  });
  return results;
}

function getCAByPath(root: RootEntry, path: number[]): CAEntry {
  let ca: CAEntry = root.CA[path[0]];
  for (let i = 1; i < path.length; i++) {
    ca = ca.CA![path[i]];
  }
  return ca;
}

function clearEndFlags(cas: CAEntry[]) {
  for (const ca of cas) {
    delete ca.end;
    if (ca.CA) clearEndFlags(ca.CA);
  }
}

function buildNameChain(root: RootEntry, path: number[]): string[] {
  const names: string[] = [];
  let ca: CAEntry = root.CA[path[0]];
  names.push(ca.caname);
  for (let i = 1; i < path.length; i++) {
    ca = ca.CA![path[i]];
    names.push(ca.caname);
  }
  return names.filter((n) => n !== "");
}

async function createRoot() {
  console.log("\n=== Root証明書の作成 ===");
  const privateKey = await question("秘密鍵 (hex): ");
  const nameca = await question("Root CA名: ");
  const keynumberStr = await question("keynumber: ");
  const keynumber = parseInt(keynumberStr);
  const caPublicKey = await question("直下CAの公開鍵 (hex): ");
  const caname = await question("直下CAの名前: ");

  const sign = p256.sign(encoder.encode(caPublicKey), privateKey);

  const cert: Certificate = {
    root: [
      {
        keynumber,
        sign,
        nameca,
        CA: [
          {
            publickey: caPublicKey,
            caname,
            signature: "",
            end: true,
          },
        ],
      },
    ],
  };

  const outPath = `./${nameca}.json`;
  fs.writeFileSync(outPath, JSON.stringify(cert, null, 2));
  console.log(`✅ 証明書を ${outPath} に保存しました`);
}

async function addToExisting() {
  let certPath = "";
  while (!certPath) {
    certPath = (await question("証明書ファイルパス: ")).trim();
    if (!certPath) console.log("ファイルパスを入力してください");
  }
  const certRaw = fs.readFileSync(certPath, "utf-8");
  const cert: Certificate = JSON.parse(certRaw);

  console.log("\nRoot一覧:");
  cert.root.forEach((r, i) => {
    console.log(`  [${i}] ${r.nameca} (keynumber: ${r.keynumber})`);
  });
  const rootIdx = parseInt(await question("Rootを選択: "));
  const root = cert.root[rootIdx];

  console.log("\nCA一覧:");
  const caList = listCAs(root.CA);

  const caIdx = parseInt(await question("追加先のCAを選択: "));
  const selectedCA = caList[caIdx];

  console.log("\n追加するものを選択:");
  console.log("  [1] CA");
  console.log("  [2] Domain");
  const addType = await question("選択: ");

  const privateKey = await question("親CAの秘密鍵 (hex): ");

  const nameChain = buildNameChain(root, selectedCA.path);
  let outName: string;

  if (addType === "1") {
    const caPublicKey = await question("新しいCAの公開鍵 (hex): ");
    const caname = await question("新しいCAの名前: ");

    const signature = p256.sign(encoder.encode(caPublicKey), privateKey);

    clearEndFlags(root.CA);

    const newCA: CAEntry = {
      publickey: caPublicKey,
      caname,
      signature,
      end: true,
    };

    const parentCA = getCAByPath(root, selectedCA.path);
    if (!parentCA.CA) parentCA.CA = [];
    delete parentCA.end;
    parentCA.CA.push(newCA);

    outName = [root.keynumber, ...nameChain, caname].join(".") + ".json";
    console.log(`✅ CA "${caname}" を追加しました`);
  } else if (addType === "2") {
    const domainname = await question("ドメイン名: ");

    const parentCA = getCAByPath(root, selectedCA.path);
    if (parentCA.domain?.some((d) => d.domainname === domainname)) {
      console.log(`❌ "${domainname}" はすでに登録されています`);
      rl.close();
      return;
    }

    const pubkey = await question("ドメインの公開鍵 (hex): ");
    const signday = new Date().toISOString().slice(0, 10);

    const domain: DomainEntry = { domainname, pubkey, signday };
    const signature = p256.sign(
      encoder.encode(canonicalJSON(domain)),
      privateKey,
    );

    if (!parentCA.domain) parentCA.domain = [];
    parentCA.domain.push(domain);
    parentCA.signature = signature;
    delete parentCA.end;

    outName = [root.keynumber, ...nameChain, domainname].join(".") + ".json";
    console.log(`✅ Domain "${domainname}" を追加しました`);
  } else {
    console.log("無効な選択です");
    return;
  }

  fs.writeFileSync(outName, JSON.stringify(cert, null, 2));
  console.log(`✅ 証明書を ${outName} に保存しました`);
}

async function main() {
  console.log("=== 証明書ツール ===");
  console.log("[1] Root証明書を作成");
  console.log("[2] 既存証明書に追加");
  const choice = await question("選択: ");

  if (choice === "1") {
    await createRoot();
  } else if (choice === "2") {
    await addToExisting();
  } else {
    console.log("無効な選択です");
  }

  rl.close();
}

main().catch(console.error);
