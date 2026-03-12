function modexp(base: bigint, exponent: bigint, modulus: bigint, modmu?: bigint, modshift?: bigint): bigint {
    function barrettReduce(
    x: bigint,
    mod: bigint,
    mu: bigint,
    shift: bigint,
  ): bigint {
    const q = (x * mu) >> shift;
    let r = x - q * mod;

    if (r >= mod) r -= mod;
    if (r >= mod) r -= mod;


    return r;
  }
  function bitLength(n: bigint): number {
    return n.toString(2).length;
  }
    if (modmu === undefined || modshift === undefined) {
    const kmod = BigInt(bitLength(modulus)) + 1n;
    modmu = modmu ?? (1n << (kmod * 2n)) / modulus;
    modshift = modshift ?? kmod * 2n;
    }
  let result = 1n;
  let b = base % modulus;
  let exp = exponent;

  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = barrettReduce(result * b, modulus, modmu, modshift);
    }
    b = barrettReduce(b * b, modulus, modmu, modshift);
    exp >>= 1n;
  }

  return result;
}


function modexpNaive(base: bigint, exp: bigint, mod: bigint) {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1n;
    }
    return result;
}

function bitLength(n:bigint) { return n.toString(2).length; }

const bigExp = 2n ** 2048n - 1n;
const bigMod = (1n << 2048n) - 1n;
// 奇数にする
const mod2048 = bigMod - 58n; // 適当な奇数offset

const a = 157891375091379013709n;
const TRIALS = 1;

// 事前計算
const kmod = BigInt(bitLength(bigMod)) + 1n;
const preMu = (1n << (kmod * 2n)) / bigMod;
const preShift = kmod * 2n;

// Barrett（事前計算あり）
const t1 = performance.now();
for (let i = 0; i < TRIALS; i++) modexp(a, bigExp, bigMod, preMu, preShift);
const t2 = performance.now();

// Barrett（事前計算なし）
const t3 = performance.now();
for (let i = 0; i < TRIALS; i++) modexp(a, bigExp, bigMod);
const t4 = performance.now();

// 素朴
const t5 = performance.now();
for (let i = 0; i < TRIALS; i++) modexpNaive(a, bigExp, bigMod);
const t6 = performance.now();

const t7 = performance.now();
for (let i = 0; i < TRIALS; i++) montgomeryModExpUltra(a, bigExp, bigMod);
const t8 = performance.now();

console.log(`--- 巨大なmodulus (2048bit), ${TRIALS}回平均 ---`);
console.log(`Barrett (事前計算あり): ${((t2-t1)/TRIALS).toFixed(4)}ms`);
console.log(`Barrett (事前計算なし): ${((t4-t3)/TRIALS).toFixed(4)}ms`);
console.log(`素朴:                   ${((t6-t5)/TRIALS).toFixed(4)}ms`);
console.log(`Montgomery:             ${((t8-t7)/TRIALS).toFixed(4)}ms`);
console.log(`事前計算ありvs素朴:     ${((t6-t5)/(t2-t1)).toFixed(2)}倍`);
console.log(`事前計算なしvs素朴:     ${((t6-t5)/(t4-t3)).toFixed(2)}倍`);
console.log(`Montgomeryvs素朴:       ${((t6-t5)/(t8-t7)).toFixed(2)}倍`);

function montgomeryModExpUltra(base: bigint, exp: bigint, mod: bigint) {
    const bitLen = (n: bigint) => n.toString(2).length;
    const modBits = bitLen(mod);

    let k;
    if (modBits >= 131072) k = 13;
    else if (modBits >= 65536) k = 12;
    else if (modBits >= 32768) k = 11;
    else if (modBits >= 16384) k = 10;
    else if (modBits >= 8192) k = 9;
    else if (modBits >= 4096) k = 8;
    else if (modBits >= 2048) k = 7;
    else if (modBits >= 1024) k = 6;
    else if (modBits >= 512) k = 5;
    else if (modBits >= 256) k = 4;
    else if (modBits >= 128) k = 3;
    else if (modBits >= 64) k = 2;
    else k = 1;

    const wsize = k;
    const R = 1n << BigInt(modBits);
    const mask = R - 1n;

    // nPrime計算
    let nPrime = mod & mask;
    for (let i = 0; i < Math.ceil(modBits / 64); i++) {
        nPrime = (nPrime * (2n - ((mod * nPrime) & mask))) & mask;
    }
    nPrime = (R - nPrime) & mask;

    // Barrett用mu/shift
    const kmod = BigInt(modBits) + 1n;
    const mu = (1n << (kmod * 2n)) / mod;
    const shift = kmod * 2n;

    const barrettReduce = (x : bigint) => {
        const q = (x * mu) >> shift;
        let r = x - q * mod;
        if (r >= mod) r -= mod;
        if (r >= mod) r -= mod;
        return r;
    };

    const montReduce = (T : bigint) => {
        const u = ((T & mask) * nPrime) & mask;
        const x = (T + u * mod) >> BigInt(modBits);
        return x >= mod ? x - mod : x;
    };

    const numOdd = 1 << (wsize - 1);
    const baseBar = barrettReduce(base << BigInt(modBits));
    const baseBar2 = montReduce(baseBar * baseBar);
    const table = new Array(numOdd);
    table[0] = baseBar;
    for (let i = 1; i < numOdd; i++) {
        table[i] = montReduce(table[i - 1] * baseBar2);
    }

    const expBin = exp.toString(2);
    let res = barrettReduce(1n << BigInt(modBits));

    for (let i = 0; i < expBin.length; ) {
        if (expBin[i] === "0") {
            res = montReduce(res * res);
            i++;
            continue;
        }
        let winLen = Math.min(wsize, expBin.length - i);
        while (winLen > 1 && expBin[i + winLen - 1] === "0") winLen--;
        const winVal = parseInt(expBin.slice(i, i + winLen), 2);
        for (let j = 0; j < winLen; j++) res = montReduce(res * res);
        if (winVal > 0) res = montReduce(res * table[(winVal - 1) >> 1]);
        i += winLen;
    }

    return montReduce(res);
}
