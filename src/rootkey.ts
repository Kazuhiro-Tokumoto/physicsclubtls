import { p_256 } from "./p-256.js";
const ec = new p_256();

interface TrustStoreEntry {
  CA: string;
  Pubkey: string; // 非圧縮 04...
}

const ROOT_KEYS: { name: string; compressed: string }[] = [
  { name: "ShudoPhysicsRootCA",  compressed: "030FB3C4DA03E4E495C56368E3C55F7846A295E1C6DA14954F8379C82586135B08" },
  { name: "ShudoPhysicsRootCA2", compressed: "02D14FC65E11D39903C95371BEDDE5556555BDF28FA66648A4B8630B2E327A6A11" },
  { name: "ShudoPhysicsRootCA3", compressed: "0305EE86431958420A4003E680A94427CD4654514477331A8566F0C055ADB2482C" },
];

export const TRUST_STORE: TrustStoreEntry[] = ROOT_KEYS.map(k => ({
  CA: k.name,
  Pubkey: "04" + ec.decompressPublicKey(k.compressed)
}));