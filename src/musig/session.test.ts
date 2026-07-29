import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, individualPubkey } from './field.js';
import { nobleVerify } from './bip340.js';
import {
  dropOneSigner,
  indistinguishability,
  loneSignerComparison,
  makeSigners,
  messageDigest,
  runSession,
} from './session.js';

const TEXT = 'Move 2 BTC to the cold wallet';

describe('runSession', () => {
  for (const n of [2, 3, 4, 5]) {
    it(`${n} signers produce one signature the plain verifier accepts`, () => {
      const r = runSession(makeSigners(n), TEXT);
      expect(r.signers).toHaveLength(n);
      expect(r.round2).toHaveLength(n);
      expect(r.allPartialsVerified).toBe(true);
      expect(r.verdict.valid).toBe(true);
      expect(r.verdict.nobleValid).toBe(true);
      expect(r.aggregation.signatureHex).toHaveLength(128); // 64 bytes
      expect(r.aggregateKeyX).toHaveLength(64); // 32 bytes
    });
  }

  it('refuses signer counts outside 2..5', () => {
    expect(() => makeSigners(1)).toThrow();
    expect(() => makeSigners(6)).toThrow();
  });

  it('signs the 32-byte digest of the typed text', () => {
    const r = runSession(makeSigners(2), TEXT);
    expect(r.messageDigest).toBe(bytesToHex(messageDigest(TEXT)));
    expect(r.messageDigest).toHaveLength(64);
    expect(r.message).toBe(TEXT);
  });

  it('records one coefficient per signer, with exactly one second-key shortcut', () => {
    const r = runSession(makeSigners(4), TEXT);
    expect(r.keyAgg.rows).toHaveLength(4);
    expect(r.keyAgg.rows.filter((row) => row.isSecondKey)).toHaveLength(1);
    expect(r.keyAgg.aggregateX).toBe(r.aggregateKeyX);
  });

  it('records two nonces per signer and the aggregate of each half', () => {
    const r = runSession(makeSigners(3), TEXT);
    expect(r.round1.pubnonces).toHaveLength(3);
    expect(r.round1.pubnonces.every((p) => p.first.length === 64 && p.second.length === 64)).toBe(true);
    expect(r.round1.agg.aggnonceHex).toHaveLength(132); // 66 bytes
    expect(r.round1.agg.first.perSigner).toHaveLength(3);
  });

  it('the R in the signature is the R the session derived', () => {
    const r = runSession(makeSigners(3), TEXT);
    expect(r.aggregation.signatureHex.slice(0, 64)).toBe(r.sessionValues.rx);
  });

  it('Σ s_i equals the s in the signature (no tweaks in play)', () => {
    const r = runSession(makeSigners(3), TEXT);
    expect(r.aggregation.sum).toBe(r.aggregation.s);
    expect(r.aggregation.signatureHex.slice(64)).toBe(r.aggregation.s);
    expect(r.aggregation.terms).toHaveLength(3);
  });

  it('KeySort changes the aggregate key but still yields a valid signature', () => {
    const signers = makeSigners(3);
    const unsorted = runSession(signers, TEXT, { sortKeys: false });
    const sorted = runSession(signers, TEXT, { sortKeys: true });
    expect(unsorted.verdict.valid).toBe(true);
    expect(sorted.verdict.valid).toBe(true);
    // Sorting is a no-op only if the keys already happened to be in order.
    const alreadySorted =
      JSON.stringify(unsorted.signers.map((s) => s.pubkey)) ===
      JSON.stringify(sorted.signers.map((s) => s.pubkey));
    if (!alreadySorted) expect(sorted.aggregateKeyX).not.toBe(unsorted.aggregateKeyX);
  });

  it('the same signers and text give the same aggregate key across runs', () => {
    const signers = makeSigners(3);
    expect(runSession(signers, TEXT).aggregateKeyX).toBe(runSession(signers, TEXT).aggregateKeyX);
  });

  it('a different message gives a different signature under the same key', () => {
    const signers = makeSigners(2);
    const a = runSession(signers, 'message A');
    const b = runSession(signers, 'message B');
    expect(a.aggregateKeyX).toBe(b.aggregateKeyX);
    expect(a.aggregation.signatureHex).not.toBe(b.aggregation.signatureHex);
  });

  it('tampering with one partial names that signer and invalidates the signature', () => {
    const r = runSession(makeSigners(3), TEXT, { tamperIndex: 1 });
    expect(r.round2.map((p) => p.verified)).toEqual([true, false, true]);
    expect(r.allPartialsVerified).toBe(false);
    expect(r.verdict.valid).toBe(false);
    expect(r.verdict.nobleValid).toBe(false);
    expect(r.verdict.disagreement).toBe(false);
  });

  it('rejects an out-of-range tamper index', () => {
    expect(() => runSession(makeSigners(2), TEXT, { tamperIndex: 5 })).toThrow(/out of range/);
  });
});

describe('indistinguishability', () => {
  it('reports 64 signature bytes and 32 key bytes regardless of signer count', () => {
    for (const n of [2, 3, 4, 5]) {
      const info = indistinguishability(runSession(makeSigners(n), TEXT));
      expect(info.signatureBytes).toBe(64);
      expect(info.aggregateKeyBytes).toBe(32);
      expect(info.signerCount).toBe(n);
      expect(info.handRolledValid).toBe(true);
      expect(info.nobleValid).toBe(true);
      expect(info.agree).toBe(true);
    }
  });

  it('the aggregate signature verifies through the stock library verifier', () => {
    const r = runSession(makeSigners(4), TEXT);
    expect(
      nobleVerify(
        hexToBytes(r.aggregation.signatureHex),
        hexToBytes(r.messageDigest),
        hexToBytes(r.aggregateKeyX),
      ),
    ).toBe(true);
  });
});

describe('loneSignerComparison — the headline claim, tested', () => {
  it('produces a real single-signer signature that the same verifier accepts', () => {
    const cmp = loneSignerComparison(runSession(makeSigners(3), TEXT));
    expect(cmp.slots).toHaveLength(2);
    for (const slot of cmp.slots) {
      expect(slot.signatureBytes).toBe(64);
      expect(slot.keyBytes).toBe(32);
      expect(slot.valid).toBe(true);
      expect(slot.nobleValid).toBe(true);
    }
  });

  it('reports the two as indistinguishable on every property it compares', () => {
    for (const n of [2, 3, 4, 5]) {
      const cmp = loneSignerComparison(runSession(makeSigners(n), TEXT));
      expect(cmp.signerCount).toBe(n);
      expect(cmp.comparedProperties.every((p) => p.same)).toBe(true);
      expect(cmp.indistinguishable).toBe(true);
    }
  });

  it('the group signature really is in the slot it claims, and the other really is not', () => {
    const r = runSession(makeSigners(3), TEXT);
    const cmp = loneSignerComparison(r);
    expect(cmp.slots[cmp.groupSlot].signatureHex).toBe(r.aggregation.signatureHex);
    expect(cmp.slots[cmp.groupSlot].keyX).toBe(r.aggregateKeyX);
    const other = cmp.slots[cmp.groupSlot === 0 ? 1 : 0];
    expect(other.signatureHex).not.toBe(r.aggregation.signatureHex);
    expect(other.keyX).not.toBe(r.aggregateKeyX);
  });

  it('the lone signature does NOT verify under the group key, and vice versa', () => {
    const r = runSession(makeSigners(2), TEXT);
    const cmp = loneSignerComparison(r);
    const lone = cmp.slots[cmp.groupSlot === 0 ? 1 : 0];
    const msg = hexToBytes(r.messageDigest);
    // Indistinguishable in shape is not interchangeable in substance.
    expect(nobleVerify(hexToBytes(lone.signatureHex), msg, hexToBytes(r.aggregateKeyX))).toBe(false);
    expect(
      nobleVerify(hexToBytes(r.aggregation.signatureHex), msg, hexToBytes(lone.keyX)),
    ).toBe(false);
  });

  it('puts the group in both slots across enough runs — the reveal is a real coin flip', () => {
    const r = runSession(makeSigners(2), TEXT);
    const slots = new Set(
      Array.from({ length: 40 }, () => loneSignerComparison(r).groupSlot),
    );
    expect(slots).toEqual(new Set([0, 1]));
  });
});

describe('per-partial group equation sides', () => {
  it('both sides match for every honest signer', () => {
    const r = runSession(makeSigners(4), TEXT);
    for (const p of r.round2) {
      expect(p.sides.equal).toBe(true);
      expect(p.sides.lhs).toBe(p.sides.rhs);
      expect(p.sides.equal).toBe(p.verified);
    }
  });

  it('the sides visibly differ for a tampered partial, and only for that one', () => {
    const r = runSession(makeSigners(3), TEXT, { tamperIndex: 1 });
    expect(r.round2.map((p) => p.sides.equal)).toEqual([true, false, true]);
    expect(r.round2[1].sides.lhs).not.toBe(r.round2[1].sides.rhs);
    // The displayed sides always agree with the boolean verdict.
    expect(r.round2.map((p) => p.sides.equal)).toEqual(r.round2.map((p) => p.verified));
  });
});

describe('secret keys exposed for checking the arithmetic', () => {
  it('each signer’s reported secret really is the key behind its public key', () => {
    const r = runSession(makeSigners(3), TEXT);
    for (const s of r.signers) {
      expect(s.secretKey).toHaveLength(64);
      expect(bytesToHex(individualPubkey(hexToBytes(s.secretKey)))).toBe(s.pubkey);
    }
  });

  it('New keys really does replace them', () => {
    const a = runSession(makeSigners(2), TEXT).signers.map((s) => s.secretKey);
    const b = runSession(makeSigners(2), TEXT).signers.map((s) => s.secretKey);
    expect(a).not.toEqual(b);
  });
});

describe('dropOneSigner — MuSig2 is n-of-n', () => {
  it('an incomplete signer set cannot produce a valid signature', () => {
    for (const n of [2, 3, 4]) {
      const r = dropOneSigner(makeSigners(n), TEXT);
      expect(r.attempted).toBe(n - 1);
      expect(r.required).toBe(n);
      expect(r.signature).toBeNull();
      expect(r.error).toMatch(/rejected/);
      expect(r.error).not.toMatch(/unexpected/);
    }
  });
});
