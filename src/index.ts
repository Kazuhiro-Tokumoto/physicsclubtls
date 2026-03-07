// index.ts — DYLA Certificate Issuer WebUI
// Build target: ./dist/client/web/index.js

import { DYLA, DYLADomain, DYLAEntry } from "./DYLA.js";
import { TRUST_STORE } from "./rootkey.js";
import { p_256 } from "./p-256.js";

const ec = new p_256();

// ===== state =====

interface State {
  step: number;
  mode: "new" | "import" | null;
  // 新規モード
  rootCAName: string;
  rootKeyPair: { privateKey: string; publicKey: string } | null;
  // インポートモード
  importedPEM: string;
  importedCert: DYLA | null;
  caPrivateKey: string;
  // チェーン構築用
  chain: DYLAEntry[];
  chainKeys: { privateKey: string; publicKey: string }[];
  currentSignerName: string;
  currentSignerKey: string;
  // 発行設定
  cn: string;
  country: string;
  state_: string;
  city: string;
  isCA: boolean;
  text: string;
  selfSigned: boolean;
  // 結果
  resultPEM: string;
  resultPrivateKey: string;
  resultPublicKey: string;
}

const state: State = {
  step: 0,
  mode: null,
  rootCAName: "",
  rootKeyPair: null,
  importedPEM: "",
  importedCert: null,
  caPrivateKey: "",
  chain: [],
  chainKeys: [],
  currentSignerName: "",
  currentSignerKey: "",
  cn: "",
  country: "JP",
  state_: "",
  city: "",
  isCA: false,
  text: "",
  selfSigned: false,
  resultPEM: "",
  resultPrivateKey: "",
  resultPublicKey: "",
};

// ===== DOM helpers =====

const $ = (id: string) => document.getElementById(id)!;

function nowISO(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function toPubkeyUncompressed(compressed: string): string {
  return "04" + ec.decompressPublicKey(compressed);
}

// ===== render =====


// Step 0: モード選択
// ===== renderStep0 差し替え =====

function renderStep0(app: HTMLElement): void {
  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">DYLA Certificate Tools</div>
      <h1>🍎 DYLA Certificate Issuer</h1>
      <p class="subtitle">Do you like apple?</p>
      <div class="button-group">
        <button id="btn-new" class="btn btn-primary">
          <span class="btn-icon">🔑</span>
          新規作成
          <span class="btn-desc">ルートCAから構築</span>
        </button>
        <button id="btn-import" class="btn btn-secondary">
          <span class="btn-icon">📄</span>
          PEMインポート
          <span class="btn-desc">既存の証明書から発行</span>
        </button>
        <button id="btn-viewer" class="btn btn-secondary">
          <span class="btn-icon">🔍</span>
          証明書ビューワー
          <span class="btn-desc">チェーン情報を表示</span>
        </button>
        <button id="btn-selfcheck" class="btn btn-secondary">
          <span class="btn-icon">✍️</span>
          自己署名チェック
          <span class="btn-desc">自己署名証明書を検証</span>
        </button>
        <button id="btn-verify" class="btn btn-secondary">
          <span class="btn-icon">🛡️</span>
          チェーン検証
          <span class="btn-desc">trust storeで検証</span>
        </button>
      </div>
    </div>
  `;
  $("btn-new").onclick = () => { state.mode = "new"; state.step = 1; render(); };
  $("btn-import").onclick = () => { state.mode = "import"; state.step = 1; render(); };
  $("btn-viewer").onclick = () => { state.mode = "viewer" as any; state.step = 10; render(); };
  $("btn-selfcheck").onclick = () => { state.step = 11; render(); };
  $("btn-verify").onclick = () => { state.step = 12; render(); };
}

// ===== renderSelfCheck 新規追加 =====

function renderSelfCheck(app: HTMLElement): void {
  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">自己署名チェック</div>
      <h2>✍️ 自己署名証明書の検証</h2>
      <div class="form-group">
        <label>DYLA PEM証明書</label>
        <textarea id="self-pem" rows="8" placeholder="-----BEGIN DYLA CERTIFICATE-----&#10;...&#10;-----END DYLA CERTIFICATE-----"></textarea>
      </div>
      <div class="form-group">
        <label>ドメイン (任意)</label>
        <input type="text" id="self-domain" placeholder="例: www.example.com" value="" />
      </div>
      <div id="self-error" class="error" style="display:none"></div>
      <div class="button-row">
        <button id="btn-back" class="btn btn-ghost">← 戻る</button>
        <button id="btn-check" class="btn btn-primary">🍎 検証</button>
      </div>
      <div id="self-result"></div>
    </div>
  `;
  $("btn-back").onclick = () => { state.step = 0; render(); };
  $("btn-check").onclick = () => {
    const pem = ($("self-pem") as HTMLTextAreaElement).value.trim();
    if (!pem) { showError("self-error", "PEMを入力してください"); return; }
    try {
      const cert = DYLA.fromPEM(pem);
      const domain = ($("self-domain") as HTMLInputElement).value.trim() || undefined;
      const result = DYLA.verifyChain(cert.raw, [], [], domain, new Date());

      $("self-error").style.display = "none";
      const el = $("self-result");

      if (result.valid) {
        let html = `<div class="verify-result verify-ok">
          <h3>✅ 自己署名検証OK</h3>
          <div class="field"><span class="label">チェーン長:</span> ${cert.chainLength}</div>
          <div class="field"><span class="label">最終CN:</span> ${cert.cn}</div>`;
        if (domain) {
          const last = cert.endEntity;
          const matched = last ? DYLA.matchDomain(last.Domain.CN, domain) : false;
          html += `<div class="field"><span class="label">ドメインマッチ:</span> 
            <span class="${matched ? "status-ok" : "status-ng"}">${matched ? "✅ " + domain + " → " + last?.Domain.CN : "❌ " + domain + " ≠ " + last?.Domain.CN}</span>
          </div>`;
        }
        html += `</div>`;
        el.innerHTML = html;
      } else {
        el.innerHTML = `<div class="verify-result verify-ng">
          <h3>❌ 検証失敗</h3>
          <div>${result.error}</div>
        </div>`;
      }
    } catch (e: any) {
      showError("self-error", e.message);
    }
  };
}

// ===== renderVerify 新規追加 =====

function renderVerify(app: HTMLElement): void {
  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">チェーン検証</div>
      <h2>🛡️ Trust Store検証</h2>
      <div class="form-group">
        <label>DYLA PEM証明書</label>
        <textarea id="verify-pem" rows="8" placeholder="-----BEGIN DYLA CERTIFICATE-----&#10;...&#10;-----END DYLA CERTIFICATE-----"></textarea>
      </div>
      <div class="form-group">
        <label>ドメイン (任意)</label>
        <input type="text" id="verify-domain" placeholder="例: www.example.com" value="" />
      </div>
      <div id="verify-error" class="error" style="display:none"></div>
      <div class="button-row">
        <button id="btn-back" class="btn btn-ghost">← 戻る</button>
        <button id="btn-verify-go" class="btn btn-primary">🍎 検証</button>
      </div>
      <div id="verify-result"></div>
    </div>
  `;
  $("btn-back").onclick = () => { state.step = 0; render(); };
  $("btn-verify-go").onclick = () => {
    const pem = ($("verify-pem") as HTMLTextAreaElement).value.trim();
    if (!pem) { showError("verify-error", "PEMを入力してください"); return; }
    try {
      const cert = DYLA.fromPEM(pem);
      const domain = ($("verify-domain") as HTMLInputElement).value.trim() || undefined;
      const result = DYLA.verifyChain(cert.raw, TRUST_STORE, [], domain);

      $("verify-error").style.display = "none";
      const el = $("verify-result");

      if (result.valid) {
        let html = `<div class="verify-result verify-ok">
          <h3>✅ チェーン検証OK</h3>
          <div class="field"><span class="label">チェーン長:</span> ${cert.chainLength}</div>
          <div class="field"><span class="label">最終CN:</span> ${cert.cn}</div>
          <div class="field"><span class="label">ルートCA:</span> ${cert.entries[0]?.CA}</div>`;
        if (domain) {
          const last = cert.endEntity;
          const matched = last ? DYLA.matchDomain(last.Domain.CN, domain) : false;
          html += `<div class="field"><span class="label">ドメインマッチ:</span> 
            <span class="${matched ? "status-ok" : "status-ng"}">${matched ? "✅ " + domain + " → " + last?.Domain.CN : "❌ " + domain + " ≠ " + last?.Domain.CN}</span>
          </div>`;
        }
        html += `</div>`;
        el.innerHTML = html;
      } else {
        el.innerHTML = `<div class="verify-result verify-ng">
          <h3>❌ 検証失敗</h3>
          <div>${result.error}</div>
        </div>`;
      }
    } catch (e: any) {
      showError("verify-error", e.message);
    }
  };
}

// ===== render 差し替え =====



// ===== renderViewer 新規追加 =====

function renderViewer(app: HTMLElement): void {
  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">証明書ビューワー</div>
      <h2>🔍 証明書情報表示</h2>
      <div class="form-group">
        <label>DYLA PEM証明書</label>
        <textarea id="viewer-pem" rows="8" placeholder="-----BEGIN DYLA CERTIFICATE-----&#10;...&#10;-----END DYLA CERTIFICATE-----"></textarea>
      </div>
      <div id="viewer-error" class="error" style="display:none"></div>
      <div class="button-row">
        <button id="btn-back" class="btn btn-ghost">← 戻る</button>
        <button id="btn-parse" class="btn btn-primary">🍎 解析</button>
      </div>
      <div id="viewer-result"></div>
    </div>
  `;
  $("btn-back").onclick = () => { state.step = 0; render(); };
  $("btn-parse").onclick = () => {
    const pem = ($("viewer-pem") as HTMLTextAreaElement).value.trim();
    if (!pem) { showError("viewer-error", "PEMを入力してください"); return; }
    try {
      const cert = DYLA.fromPEM(pem);
      const result = $("viewer-result");
      $("viewer-error").style.display = "none";

      let html = `<div class="viewer-info">`;
      html += `<div class="viewer-summary">
        <h3>チェーン概要</h3>
        <div class="field"><span class="label">エントリ数:</span> ${cert.chainLength}</div>
        <div class="field"><span class="label">最終CN:</span> ${cert.cn}</div>
        <div class="field"><span class="label">種別:</span> ${cert.endEntity?.Domain.IsCA ? "CA証明書" : "エンドエンティティ証明書"}</div>
      </div>`;

      cert.entries.forEach((entry, i) => {
        const expired = DYLA.isExpired(entry);
        const serialValid = DYLA.verifySerial(entry);
        const validityDays = entry.Domain.IsCA ? "5年" : "90日";
        const issuedAt = new Date(entry.Domain.IssuedAt);
        const expiresAt = new Date(issuedAt.getTime() + (entry.Domain.IsCA ? 5 * 365.25 * 24 * 60 * 60 * 1000 : 90 * 24 * 60 * 60 * 1000));

        html += `
          <div class="viewer-entry">
            <div class="viewer-entry-header">
              <span class="chain-order">${entry.Order}</span>
              <strong>${entry.Domain.CN}</strong>
              <span class="tag ${entry.Domain.IsCA ? "tag-ca" : "tag-ee"}">${entry.Domain.IsCA ? "CA" : "End-Entity"}</span>
              <span class="tag ${expired ? "tag-expired" : "tag-valid"}">${expired ? "期限切れ" : "有効"}</span>
            </div>
            <div class="viewer-entry-body">
              <div class="viewer-section">
                <h4>Subject</h4>
                <div class="field"><span class="label">CN:</span> ${entry.Domain.CN}</div>
                <div class="field"><span class="label">Country:</span> ${entry.Domain.Country}</div>
                <div class="field"><span class="label">State:</span> ${entry.Domain.State}</div>
                <div class="field"><span class="label">City:</span> ${entry.Domain.City}</div>
                <div class="field"><span class="label">IsCA:</span> ${entry.Domain.IsCA}</div>
              </div>
              <div class="viewer-section">
                <h4>公開鍵</h4>
                <code class="mono pubkey-display">${entry.Domain.Pubkey}</code>
              </div>
              <div class="viewer-section">
                <h4>発行情報</h4>
                <div class="field"><span class="label">発行者 (CA):</span> ${entry.CA}</div>
                <div class="field"><span class="label">発行日:</span> ${entry.Domain.IssuedAt}</div>
                <div class="field"><span class="label">有効期限:</span> ${expiresAt.toISOString().replace(/\.\d{3}Z$/, "Z")} (${validityDays})</div>
                <div class="field"><span class="label">Order:</span> ${entry.Order}</div>
              </div>
              <div class="viewer-section">
                <h4>署名・シリアル</h4>
                <div class="field"><span class="label">Sig:</span><code class="mono sig-display">${entry.Sig}</code></div>
                <div class="field"><span class="label">Serial:</span><code class="mono">${entry.Serial}</code></div>
                <div class="field"><span class="label">Serial整合性:</span> <span class="${serialValid ? "status-ok" : "status-ng"}">${serialValid ? "✅ OK" : "❌ 不一致"}</span></div>
              </div>
              ${entry.Text ? `<div class="viewer-section"><h4>Text</h4><div>${entry.Text}</div></div>` : ""}
              <div class="viewer-section">
                <div class="field"><span class="label">Message:</span> ${entry.Message}</div>
              </div>
            </div>
          </div>
        `;
      });

      // JSON生データ
      html += `
        <div class="viewer-section">
          <h3>JSON (生データ)</h3>
          <textarea class="json-raw" rows="12" readonly>${JSON.stringify(cert.raw, null, 2)}</textarea>
        </div>
      `;

      html += `</div>`;
      result.innerHTML = html;
    } catch (e: any) {
      showError("viewer-error", e.message);
    }
  };
}

// ===== render 差し替え（step 10を追加） =====

function render(): void {
  const app = $("app");
  switch (state.step) {
    case 0: renderStep0(app); break;
    case 1: renderStep1(app); break;
    case 2: renderStep2(app); break;
    case 3: renderStep3(app); break;
    case 10: renderViewer(app); break;
    case 11: renderSelfCheck(app); break;
    case 12: renderVerify(app); break;
  }
}

// ===== Step 1のrender関数を丸ごと差し替え =====

function renderStep1(app: HTMLElement): void {
  if (state.mode === "new") {
    app.innerHTML = `
      <div class="card">
        <div class="step-indicator">Step 2 / 4</div>
        <h2>ルートCA設定</h2>
        <div class="form-group">
          <label>ルートCA名</label>
          <input type="text" id="root-ca-name" placeholder="例: ShudoPhysicsRootCA" value="${state.rootCAName}" />
        </div>
        <div class="form-group">
          <label>秘密鍵 (hex) — 空欄で自動生成</label>
          <input type="text" id="root-privkey" placeholder="秘密鍵を入力 or 空欄" value="" />
        </div>
        <div class="form-group">
          <label class="toggle-label">
            <input type="checkbox" id="toggle-selfsigned" ${state.selfSigned ? "checked" : ""} />
            <span class="toggle-switch"></span>
            自己署名ルートCA（trust store 不要）
          </label>
          <p class="toggle-desc">ONにすると、この証明書チェーンを検証する際にtrust storeへの登録が不要になります。</p>
        </div>
        <div id="root-key-info" class="key-info" style="display:none"></div>
        <div id="root-error" class="error" style="display:none"></div>
        <div class="button-row">
          <button id="btn-back" class="btn btn-ghost">← 戻る</button>
          <button id="btn-gen" class="btn btn-primary">確定</button>
          <button id="btn-next" class="btn btn-primary" style="display:none">次へ →</button>
        </div>
      </div>
    `;
    $("btn-back").onclick = () => { state.step = 0; render(); };
    $("btn-gen").onclick = () => {
      const name = ($("root-ca-name") as HTMLInputElement).value.trim();
      if (!name) { showError("root-error", "CA名を入力してください"); return; }
      state.rootCAName = name;

      try {
        const privInput = ($("root-privkey") as HTMLInputElement).value.trim();
        if (privInput) {
          const pub = ec.privateKeyToPublicKey(privInput);
          state.rootKeyPair = { privateKey: privInput, publicKey: pub.compressed };
        } else {
          const kp = DYLA.generateKeyPair();
          // generateKeyPair()は非圧縮(04+XY)を返すが、UIでは圧縮形式で扱う
          const pub = ec.privateKeyToPublicKey(kp.privateKey);
          state.rootKeyPair = { privateKey: kp.privateKey, publicKey: pub.compressed };
        }
      } catch (e: any) {
        showError("root-error", "秘密鍵が無効です: " + e.message);
        return;
      }

      state.currentSignerName = name;
      state.currentSignerKey = state.rootKeyPair.privateKey;
      const info = $("root-key-info");
      info.style.display = "block";
      info.innerHTML = `
        <div class="field"><span class="label">公開鍵 (compressed):</span><code class="mono">${state.rootKeyPair.publicKey}</code></div>
        <div class="field"><span class="label">公開鍵 (uncompressed):</span><code class="mono">04${ec.decompressPublicKey(state.rootKeyPair.publicKey)}</code></div>
        <div class="field"><span class="label">秘密鍵:</span><code class="mono secret">${state.rootKeyPair.privateKey}</code></div>
        <p class="warn">⚠ 秘密鍵は安全に保管してください</p>
      `;
      ($("btn-gen") as HTMLButtonElement).style.display = "none";
      ($("btn-next") as HTMLButtonElement).style.display = "inline-flex";
    };
    $("btn-next")!.onclick = () => {
      state.selfSigned = ($("toggle-selfsigned") as HTMLInputElement).checked;
      state.step = 2;
      render();
    };
  } else {
    app.innerHTML = `
      <div class="card">
        <div class="step-indicator">Step 2 / 4</div>
        <h2>PEMインポート</h2>
        <div class="form-group">
          <label>DYLA PEM証明書</label>
          <textarea id="pem-input" rows="8" placeholder="-----BEGIN DYLA CERTIFICATE-----&#10;...&#10;-----END DYLA CERTIFICATE-----">${state.importedPEM}</textarea>
        </div>
        <div class="form-group">
          <label>CA秘密鍵 (hex)</label>
          <input type="text" id="ca-privkey" placeholder="最後のCAエントリの秘密鍵" value="${state.caPrivateKey}" />
        </div>
        <div id="import-error" class="error" style="display:none"></div>
        <div class="button-row">
          <button id="btn-back" class="btn btn-ghost">← 戻る</button>
          <button id="btn-import-go" class="btn btn-primary">インポート →</button>
        </div>
      </div>
    `;
    $("btn-back").onclick = () => { state.step = 0; render(); };
    $("btn-import-go").onclick = () => {
      const pem = ($("pem-input") as HTMLTextAreaElement).value.trim();
      const privKey = ($("ca-privkey") as HTMLInputElement).value.trim();
      if (!pem || !privKey) { showError("import-error", "PEMと秘密鍵を入力してください"); return; }
      try {
        const cert = DYLA.fromPEM(pem);
        const last = cert.endEntity;
        if (!last) { showError("import-error", "空の証明書チェーンです"); return; }
        if (!last.Domain.IsCA) { showError("import-error", "最後のエントリがCAではありません"); return; }
        state.importedPEM = pem;
        state.importedCert = cert;
        state.caPrivateKey = privKey;
        state.chain = [...cert.entries];
        state.currentSignerName = last.Domain.CN;
        state.currentSignerKey = privKey;
        state.step = 2;
        render();
      } catch (e: any) {
        showError("import-error", e.message);
      }
    };
  }
}

// ===== Step 2のrender関数を丸ごと差し替え =====

function renderStep2(app: HTMLElement): void {
  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">Step 3 / 4</div>
      <h2>証明書情報</h2>
      <p class="signer-info">署名者: <strong>${state.currentSignerName}</strong></p>
      <div class="form-group">
        <label>発行する証明書の公開鍵 (hex, 圧縮 or 非圧縮) — 空欄で自動生成</label>
        <input type="text" id="cert-pubkey" placeholder="02... / 03... / 04..." value="" />
      </div>
      <div class="form-row">
        <div class="form-group flex-2">
          <label>CN (Common Name)</label>
          <input type="text" id="cert-cn" placeholder="例: *.example.com" value="${state.cn}" />
        </div>
        <div class="form-group flex-1">
          <label>種別</label>
          <select id="cert-isca">
            <option value="false" ${!state.isCA ? "selected" : ""}>エンドエンティティ</option>
            <option value="true" ${state.isCA ? "selected" : ""}>中間CA</option>
          </select>
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>Country (ISO 2文字)</label>
          <input type="text" id="cert-country" maxlength="2" placeholder="JP" value="${state.country}" />
        </div>
        <div class="form-group">
          <label>State</label>
          <input type="text" id="cert-state" placeholder="Hiroshima" value="${state.state_}" />
        </div>
        <div class="form-group">
          <label>City</label>
          <input type="text" id="cert-city" placeholder="Hiroshima" value="${state.city}" />
        </div>
      </div>
      <div class="form-group">
        <label>Text (任意)</label>
        <input type="text" id="cert-text" placeholder="コメント" value="${state.text}" />
      </div>
      <div id="issue-error" class="error" style="display:none"></div>
      <div class="button-row">
        <button id="btn-back" class="btn btn-ghost">← 戻る</button>
        <button id="btn-issue" class="btn btn-primary">🍎 発行</button>
      </div>
    </div>
  `;
  $("btn-back").onclick = () => { state.step = 1; render(); };
  $("btn-issue").onclick = () => {
    try {
      state.cn = ($("cert-cn") as HTMLInputElement).value.trim();
      state.isCA = ($("cert-isca") as HTMLSelectElement).value === "true";
      state.country = ($("cert-country") as HTMLInputElement).value.trim().toUpperCase();
      state.state_ = ($("cert-state") as HTMLInputElement).value.trim();
      state.city = ($("cert-city") as HTMLInputElement).value.trim();
      state.text = ($("cert-text") as HTMLInputElement).value;

      if (!state.cn) { showError("issue-error", "CNを入力してください"); return; }
      if (state.country.length !== 2) { showError("issue-error", "Countryは2文字のISO国コード (例: JP)"); return; }

      // 公開鍵: 入力 or 自動生成
      const pubInput = ($("cert-pubkey") as HTMLInputElement).value.trim();
      let pubkeyUncompressed: string;
      let resultPrivateKey: string = "";

      if (pubInput) {
        if (pubInput.startsWith("04") && pubInput.length === 130) {
          pubkeyUncompressed = pubInput;
        } else if ((pubInput.startsWith("02") || pubInput.startsWith("03")) && pubInput.length === 66) {
          pubkeyUncompressed = "04" + ec.decompressPublicKey(pubInput);
        } else {
          showError("issue-error", "公開鍵の形式が無効です (02/03で66文字 or 04で130文字)");
          return;
        }
      } else if (state.mode === "new" && state.chain.length === 0 && state.selfSigned) {
        // 自己署名ルートCA: 署名者(=自分)の公開鍵をDomain.Pubkeyに設定
        // state.rootKeyPairの公開鍵は圧縮形式(66文字)なので非圧縮に変換
        const rootPub = state.rootKeyPair!.publicKey;
        if (rootPub.startsWith("04") && rootPub.length === 130) {
          pubkeyUncompressed = rootPub;
        } else {
          pubkeyUncompressed = "04" + ec.decompressPublicKey(rootPub);
        }
        resultPrivateKey = state.rootKeyPair!.privateKey;
      } else {
        const keyPair = DYLA.generateKeyPair();
        // generateKeyPair() は "04" + XY (130文字) を返すのでそのまま使用
        pubkeyUncompressed = keyPair.publicKey;
        resultPrivateKey = keyPair.privateKey;
      }

      const order = state.chain.length;

      const domain: DYLADomain = {
        CN: state.cn,
        IsCA: state.isCA,
        Pubkey: pubkeyUncompressed,
        Country: state.country,
        State: state.state_,
        City: state.city,
        IssuedAt: nowISO()
      };

      const entry = DYLA.createEntry(
        state.currentSignerName,
        order,
        domain,
        state.currentSignerKey,
        state.text,
        state.mode === "new" && order === 0 ? state.selfSigned : false
      );

      const certEntries = [...state.chain, entry];
      const cert = new DYLA({ DYLA: certEntries });

      state.resultPEM = cert.toPEM();
      state.resultPrivateKey = resultPrivateKey;
      state.resultPublicKey = pubkeyUncompressed;

      if (state.isCA) {
        state.chain = certEntries;
        state.currentSignerName = state.cn;
        // 自動生成時のみsigner keyを更新（手動入力時は秘密鍵を知らないから続けて発行不可）
        if (resultPrivateKey) {
          state.currentSignerKey = resultPrivateKey;
        }
      }

      state.step = 3;
      render();
    } catch (e: any) {
      showError("issue-error", e.message);
    }
  };
}

// ===== Step 3も差し替え（秘密鍵表示の条件分岐） =====

function renderStep3(app: HTMLElement): void {
  const cert = DYLA.fromPEM(state.resultPEM);
  const chainHTML = cert.entries.map((e, i) => `
    <div class="chain-entry">
      <div class="chain-order">${e.Order}</div>
      <div class="chain-detail">
        <strong>${e.Domain.CN}</strong>
        <span class="tag ${e.Domain.IsCA ? "tag-ca" : "tag-ee"}">${e.Domain.IsCA ? "CA" : "End-Entity"}</span>
        <div class="chain-meta">${e.Domain.Country} / ${e.Domain.State} / ${e.Domain.City} — 署名者: ${e.CA}</div>
      </div>
    </div>
  `).join("");

  const privKeyHTML = state.resultPrivateKey ? `
    <div class="form-group">
      <label>秘密鍵 (hex) — 自動生成</label>
      <div class="secret-box">
        <code id="result-privkey" class="mono secret">${state.resultPrivateKey}</code>
        <button id="btn-copy-priv" class="btn btn-small">コピー</button>
      </div>
      <p class="warn">⚠ この秘密鍵は二度と表示されません。安全に保管してください。</p>
    </div>
  ` : `
    <p class="signer-info">秘密鍵: 公開鍵を手動入力したため表示なし</p>
  `;

  // 中間CAで続けて発行できるのは秘密鍵を知ってる場合のみ
  const canContinue = state.isCA && state.resultPrivateKey;

  app.innerHTML = `
    <div class="card">
      <div class="step-indicator">Step 4 / 4</div>
      <h2>🍎 発行完了</h2>
      <div class="chain-view">
        <h3>証明書チェーン</h3>
        ${chainHTML}
      </div>
      <div class="form-group">
        <label>PEM証明書</label>
        <textarea id="result-pem" rows="10" readonly>${state.resultPEM}</textarea>
        <button id="btn-copy-pem" class="btn btn-small">コピー</button>
      </div>
      ${privKeyHTML}
      <div class="button-row">
        ${canContinue ? `<button id="btn-continue" class="btn btn-secondary">この中間CAで続けて発行 →</button>` : ""}
        <button id="btn-restart" class="btn btn-primary">最初から</button>
      </div>
    </div>
  `;

  $("btn-copy-pem").onclick = () => copyText(state.resultPEM);
  if (state.resultPrivateKey) {
    $("btn-copy-priv").onclick = () => copyText(state.resultPrivateKey);
  }
  $("btn-restart").onclick = () => { resetState(); render(); };
  if (canContinue && $("btn-continue")) {
    $("btn-continue")!.onclick = () => { state.step = 2; render(); };
  }
}

// ===== utilities =====

function showError(id: string, msg: string): void {
  const el = $(id);
  el.textContent = "❌ " + msg;
  el.style.display = "block";
}

function copyText(text: string): void {
  navigator.clipboard.writeText(text).then(() => {
    // 簡易フィードバック
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = "コピーしました";
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 1500);
  });
}

function resetState(): void {
  state.step = 0;
  state.mode = null;
  state.rootCAName = "";
  state.rootKeyPair = null;
  state.importedPEM = "";
  state.importedCert = null;
  state.caPrivateKey = "";
  state.chain = [];
  state.chainKeys = [];
  state.currentSignerName = "";
  state.currentSignerKey = "";
  state.cn = "";
  state.country = "JP";
  state.state_ = "";
  state.city = "";
  state.isCA = false;
  state.text = "";
  state.selfSigned = false;
  state.resultPEM = "";
  state.resultPrivateKey = "";
  state.resultPublicKey = "";
}

// ===== CSS injection =====

function injectStyles(): void {
  const style = document.createElement("style");
  style.textContent = `
    :root {
      --bg: #0a0a0f;
      --card: #12121a;
      --border: #1e1e2e;
      --text: #e0e0e8;
      --text-dim: #888899;
      --accent: #4ade80;
      --accent-dim: #22763a;
      --danger: #f87171;
      --mono-bg: #1a1a2a;
      --radius: 12px;
    }

    body {
      background: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      padding: 24px 16px;
      min-height: 100vh;
    }

    #app {
      width: 100%;
      max-width: 640px;
    }

    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 32px;
    }

    .step-indicator {
      font-size: 12px;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 8px;
    }

    h1 {
      font-size: 28px;
      margin: 0 0 4px;
    }

    h2 {
      font-size: 22px;
      margin: 0 0 20px;
    }

    h3 {
      font-size: 16px;
      margin: 0 0 12px;
      color: var(--text-dim);
    }

    .subtitle {
      color: var(--text-dim);
      margin: 0 0 28px;
      font-style: italic;
    }

    .signer-info {
      color: var(--text-dim);
      margin: 0 0 20px;
      font-size: 14px;
    }

.button-group {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
}

.btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
  padding: 20px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: transparent;
  color: var(--text);
  cursor: pointer;
  font-family: inherit;
  font-size: 15px;
  transition: all 0.15s;
  text-align: center;
  width: 100%;
  box-sizing: border-box;
}

    .btn:hover {
      border-color: var(--accent);
      background: var(--accent-dim);
    }

    .btn-primary {
      background: var(--accent-dim);
      border-color: var(--accent);
      color: var(--accent);
      flex-direction: row;
    }

    .btn-secondary {
      flex-direction: row;
    }

    .btn-ghost {
      border: none;
      color: var(--text-dim);
      flex-direction: row;
      padding: 8px 16px;
    }

    .btn-ghost:hover {
      color: var(--text);
      background: transparent;
    }

    .btn-small {
      padding: 4px 12px;
      font-size: 12px;
      flex-direction: row;
      margin-top: 6px;
    }

    .btn-icon {
      font-size: 24px;
    }

    .btn-desc {
      font-size: 12px;
      color: var(--text-dim);
    }

    .button-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 24px;
      gap: 12px;
    }

    .form-group {
      margin-bottom: 16px;
    }

    .form-row {
      display: flex;
      gap: 12px;
    }

    .form-row .form-group {
      flex: 1;
    }

    .flex-2 { flex: 2 !important; }
    .flex-1 { flex: 1 !important; }

    label {
      display: block;
      font-size: 13px;
      color: var(--text-dim);
      margin-bottom: 6px;
    }

    input, textarea, select {
      width: 100%;
      padding: 10px 12px;
      background: var(--mono-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-family: inherit;
      font-size: 14px;
      box-sizing: border-box;
    }

    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--accent);
    }

    textarea {
      resize: vertical;
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 12px;
    }

    .mono {
      font-family: 'SF Mono', 'Fira Code', monospace;
      font-size: 12px;
      word-break: break-all;
    }

    .secret {
      color: var(--danger);
    }

    .key-info {
      background: var(--mono-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin: 16px 0;
    }

    .field {
      margin-bottom: 8px;
    }

    .field .label {
      font-size: 12px;
      color: var(--text-dim);
      display: block;
      margin-bottom: 2px;
    }

    .warn {
      color: var(--danger);
      font-size: 12px;
      margin: 8px 0 0;
    }

    .error {
      color: var(--danger);
      font-size: 14px;
      padding: 8px 12px;
      background: rgba(248, 113, 113, 0.1);
      border-radius: 6px;
      margin: 12px 0;
    }

    .chain-view {
      margin-bottom: 20px;
    }

    .chain-entry {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px;
      border-left: 2px solid var(--accent);
      margin-bottom: 8px;
    }

    .chain-order {
      font-size: 20px;
      font-weight: bold;
      color: var(--accent);
      min-width: 28px;
      text-align: center;
    }

    .chain-detail {
      font-size: 14px;
    }

    .chain-meta {
      font-size: 12px;
      color: var(--text-dim);
      margin-top: 2px;
    }

    .tag {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      margin-left: 8px;
    }

    .tag-ca {
      background: var(--accent-dim);
      color: var(--accent);
    }

    .tag-ee {
      background: rgba(99, 102, 241, 0.2);
      color: #818cf8;
    }

    .secret-box {
      background: var(--mono-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
    }

    .toast {
      position: fixed;
      bottom: 24px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--accent);
      color: var(--bg);
      padding: 8px 20px;
      border-radius: 20px;
      font-size: 14px;
      animation: fadeout 1.5s forwards;
    }

    @keyframes fadeout {
      0%, 60% { opacity: 1; }
      100% { opacity: 0; }
    }

    @media (max-width: 480px) {
      .form-row { flex-direction: column; gap: 0; }
      .button-group { flex-direction: column; }
      .card { padding: 20px; }
    }
      .viewer-info {
  margin-top: 24px;
}

.viewer-summary {
  background: var(--mono-bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
}

.viewer-entry {
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
}

.viewer-entry-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  background: var(--mono-bg);
  border-bottom: 1px solid var(--border);
}

.viewer-entry-body {
  padding: 16px;
}

.viewer-section {
  margin-bottom: 16px;
}

.viewer-section h4 {
  font-size: 13px;
  color: var(--accent);
  margin: 0 0 8px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.pubkey-display, .sig-display {
  display: block;
  word-break: break-all;
  font-size: 11px;
  background: var(--mono-bg);
  padding: 8px;
  border-radius: 4px;
}

.json-raw {
  width: 100%;
  font-family: 'SF Mono', 'Fira Code', monospace;
  font-size: 11px;
  background: var(--mono-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  padding: 12px;
  resize: vertical;
  box-sizing: border-box;
}

.status-ok { color: var(--accent); }
.status-ng { color: var(--danger); }

.toggle-label {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  font-size: 14px;
  color: var(--text);
  user-select: none;
}

.toggle-label input[type="checkbox"] {
  display: none;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 40px;
  height: 22px;
  background: var(--border);
  border-radius: 11px;
  flex-shrink: 0;
  transition: background 0.2s;
}

.toggle-switch::after {
  content: "";
  position: absolute;
  top: 3px;
  left: 3px;
  width: 16px;
  height: 16px;
  background: var(--text-dim);
  border-radius: 50%;
  transition: transform 0.2s, background 0.2s;
}

.toggle-label input[type="checkbox"]:checked + .toggle-switch {
  background: var(--accent-dim);
  border: 1px solid var(--accent);
}

.toggle-label input[type="checkbox"]:checked + .toggle-switch::after {
  transform: translateX(18px);
  background: var(--accent);
}

.toggle-desc {
  font-size: 12px;
  color: var(--text-dim);
  margin: 6px 0 0;
}

.tag-expired {
  background: rgba(248, 113, 113, 0.2);
  color: var(--danger);
}

.tag-valid {
  background: rgba(74, 222, 128, 0.2);
  color: var(--accent);
}                      // ← ここで .tag-valid を正しく閉じる

.verify-result {       // ← 独立したルールとして外に出す
  margin-top: 20px;
  padding: 16px;
  border-radius: 8px;
}

.verify-ok {
  background: rgba(74, 222, 128, 0.1);
  border: 1px solid var(--accent);
}

.verify-ng {
  background: rgba(248, 113, 113, 0.1);
  border: 1px solid var(--danger);
}
  `;
  document.head.appendChild(style);
}

// ===== init =====

function init(): void {
  injectStyles();
  const app = document.createElement("div");
  app.id = "app";
  document.body.appendChild(app);
  render();
}

init();