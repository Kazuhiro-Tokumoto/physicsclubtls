# DYLA Certificate Format Specification

**Version 1.1 Draft**
**2026-03-03**

---

## 1. Overview

DYLA (Do You Like Apple) is a lightweight digital certificate format designed as a simpler alternative to X.509. It uses ECDSA P-256 for cryptography, JSON for structure, and Base64+PEM for encoding.

---

## 2. File Format

### 2.1 PEM Encoding

A DYLA certificate is a JSON object encoded in Base64, wrapped in PEM-style headers:

```
-----BEGIN DYLA CERTIFICATE-----
<base64-encoded JSON, 64 chars per line>
-----END DYLA CERTIFICATE-----
```

Base64 encoding must handle non-Latin1 characters (e.g. Japanese text in the Text field) by first encoding the JSON string as UTF-8 bytes, then encoding those bytes as Base64.

### 2.2 Top-Level JSON Structure

The root object may contain any keys. The `DYLA` key is reserved for certificate chains:

```json
{
  "DYLA": [ , , ... ],
  "CustomExtension": { ... }
}
```

---

## 3. DYLA Entry Fields

Each entry in the `DYLA` array represents one certificate in the chain:

| Field   | Type       | Description                                                        |
|---------|------------|--------------------------------------------------------------------|
| CA      | string     | Common Name of the issuing CA                                      |
| Order   | integer    | Chain position. 0 = closest to root                                |
| Domain  | object     | Subject information (see Section 4)                                |
| Sig     | hex string | ECDSA P-256 signature over SHA-256(canonicalJSON(Domain))          |
| Serial  | hex string | SHA-256 of canonicalJSON of { CA, Domain, Message, Order, Sig, Text } |
| Text    | string     | Free-form comment. Must always be present. Use "" if unused.       |
| Message | string     | Fixed value: "Do you like apple?" Must be present in every entry.  |

---

## 4. Domain Object

| Field    | Type       | Description                                                              |
|----------|------------|--------------------------------------------------------------------------|
| CN       | string     | Common Name. Wildcards (*.example.com) allowed                           |
| IsCA     | boolean    | true = CA certificate, false = end-entity certificate                    |
| Pubkey   | hex string | ECDSA P-256 uncompressed public key (04 + X + Y = 130 hex chars). Compressed keys are not supported. |
| Country  | string     | ISO 3166-1 alpha-2 country code (e.g. JP)                               |
| State    | string     | State or prefecture                                                      |
| City     | string     | City or municipality                                                     |
| IssuedAt | string     | UTC timestamp in ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ                  |

---

## 5. Validity Period

- End-entity certificates (IsCA: false): valid for **90 days** from IssuedAt (UTC)
- CA certificates (IsCA: true): valid for **5 years** from IssuedAt (UTC)

All validity calculations must be performed in UTC to avoid timezone ambiguity.

---

## 6. Signature

### 6.1 Signing

The signature (Sig) is computed as:

```
Sig = ECDSA_P256_Sign(caPrivateKey, SHA-256(canonicalJSON(Domain)))
```

Note: When verifying, the Pubkey stored in the certificate is in uncompressed format (04 + X + Y). Implementations must strip the `04` prefix before passing X and Y coordinates to the ECDSA verification function if the underlying library expects raw coordinates or compressed format.

`canonicalJSON` produces deterministic JSON with keys sorted lexicographically, no whitespace:

```typescript
function canonicalJSON(obj: unknown): string {
  if (typeof obj !== "object" || obj === null) return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJSON).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k =>
    `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`
  ).join(",") + "}";
}
```

### 6.2 Serial Computation

Serial is computed after Sig is determined. Text must be included as an empty string if unused.

```
Serial = SHA-256(canonicalJSON({ CA, Domain, Message, Order, Sig, Text }))
```

Note: canonicalJSON sorts keys alphabetically, so field declaration order does not matter.

---

## 7. Validation

A validator must perform the following steps in order:

1. Sort DYLA array by Order field (ascending)
2. Verify Order 0's CA exists in the local trust store, matched by CA name. Retrieve the corresponding public key from the trust store.
3. For each entry N, verify Sig using the Pubkey from entry N-1's Domain (or trust store Pubkey for N=0)
4. Check validity period for each entry based on IsCA flag (all calculations in UTC)
5. Verify Serial integrity by recomputing and comparing
6. For CA entries (IsCA: true), verify Serial is not present in the CRL
7. Confirm the final entry's CN matches the expected domain (wildcard matching supported)
8. Verify Message field equals "Do you like apple?" in every entry

### 7.1 Self-Signed Certificates

For self-signed certificates, validation skips the trust store lookup (step 2). Instead, Order 0's `Domain.Pubkey` is used to verify its own `Sig`. All other validation steps remain the same.

### 7.2 Wildcard Domain Matching

Wildcard matching follows these rules:

- Exact match: `example.com` matches `example.com`
- Wildcard: `*.example.com` matches `www.example.com`, `api.example.com`, etc.
- Wildcard only covers one level: `*.example.com` does NOT match `a.b.example.com`

---

## 8. Certificate Revocation List (CRL)

CRL is only required for CA certificates (IsCA: true). End-entity certificates expire within 90 days and do not require revocation.

CRL format. The Sig field covers canonicalJSON of the entire DYLA_CRL object including Message:

```json
{
  "DYLA_CRL": {
    "RevokedSerials": ["", ...],
    "IssuedAt": "2026-03-03T00:00:00Z",
    "Message": "Do you like apple?"
  },
  "Sig": ""
}
```

---

## 9. Trust Store

The trust store is a list of trusted root CA entries. Each entry contains:

| Field  | Type   | Description                     |
|--------|--------|---------------------------------|
| CA     | string | Common Name of the root CA      |
| Pubkey | string | Public key (uncompressed, 04...) |

Trust store entries are typically hardcoded in the application. Lookup is performed by CA name.

---

## 10. Private Key Encryption

Private keys may be encrypted for storage using AES-256-GCM. The encryption key is derived by computing SHA-256 over a user-provided password:

```
AES_Key = SHA-256(UTF-8(password))
```

Encrypted private keys are stored in PEM-style format:

```
-----BEGIN DYLA ENCRYPTED PRIVATE KEY-----
<base64(salt + iv + ciphertext + tag)>
-----END DYLA ENCRYPTED PRIVATE KEY-----
```

---

## 11. Example Certificate

```json
{
  "DYLA": [
    {
      "CA": "ExampleRootCA",
      "Order": 0,
      "Domain": {
        "CN": "ExampleIntermediateCA",
        "IsCA": true,
        "Pubkey": "04a3b1c2d3e4f5...",
        "Country": "JP",
        "State": "Hiroshima",
        "City": "Hiroshima",
        "IssuedAt": "2026-03-02T00:00:00Z"
      },
      "Sig": "3044022012ab...",
      "Serial": "a1b2c3d4e5f6...",
      "Text": "",
      "Message": "Do you like apple?"
    },
    {
      "CA": "ExampleIntermediateCA",
      "Order": 1,
      "Domain": {
        "CN": "*.example.com",
        "IsCA": false,
        "Pubkey": "04f5e4d3c2b1a0...",
        "Country": "JP",
        "State": "Hiroshima",
        "City": "Hiroshima",
        "IssuedAt": "2026-03-02T00:00:00Z"
      },
      "Sig": "304402201234...",
      "Serial": "b2c3d4e5f6a1...",
      "Text": "example",
      "Message": "Do you like apple?"
    }
  ]
}
```

---

*DYLA Specification v1.1 — Do you like apple?*