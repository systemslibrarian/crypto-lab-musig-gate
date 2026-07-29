/**
 * The official BIP-327 test vectors, run against this lab's implementation.
 *
 * These are the spec's own known-answer tests, copied verbatim from
 * bitcoin/bips/bip-0327/vectors/*.json — not vectors we generated from our own
 * code, which would prove only that the code agrees with itself. They cover key
 * aggregation, nonce generation, nonce aggregation, partial signing, partial
 * verification, tweaking, deterministic signing, and signature aggregation,
 * including every malformed-input case the spec enumerates.
 *
 * The signature-aggregation vectors go one step further: each one asserts that the
 * aggregated result verifies under a plain BIP-340 verifier. That is this lab's
 * headline claim, checked against the specification's own bytes.
 *
 * Every runner returns structured results so the same code drives both the Vitest
 * suite and the in-page KAT table — the table on the page is not a screenshot of a
 * test run, it is the test run.
 */
import keyAggVectors from './vectors/key_agg_vectors.json';
import nonceGenVectors from './vectors/nonce_gen_vectors.json';
import nonceAggVectors from './vectors/nonce_agg_vectors.json';
import signVerifyVectors from './vectors/sign_verify_vectors.json';
import tweakVectors from './vectors/tweak_vectors.json';
import detSignVectors from './vectors/det_sign_vectors.json';
import sigAggVectors from './vectors/sig_agg_vectors.json';

import { bytesToHex, hexToBytes, individualPubkey } from './field.js';
import { nobleVerify } from './bip340.js';
import { InvalidContributionError, getXonlyPk, keyAgg, keyAggAndTweak } from './keyagg.js';
import { nonceAgg, nonceGenInternal } from './nonce.js';
import {
  type SessionContext,
  deterministicSign,
  partialSigAgg,
  partialSigVerify,
  partialSigVerifyInternal,
  sign,
} from './sign.js';

/** One executed known-answer test. */
export interface KatResult {
  group: string;
  index: number;
  /** What the case checks, in a sentence. */
  what: string;
  /** "accept" for valid vectors, "reject" for the spec's error/failure vectors. */
  kind: 'accept' | 'reject';
  pass: boolean;
  expected: string;
  actual: string;
}

export interface KatGroup {
  id: string;
  title: string;
  file: string;
  blurb: string;
}

export const KAT_GROUPS: KatGroup[] = [
  {
    id: 'key_agg',
    title: 'Key aggregation',
    file: 'key_agg_vectors.json',
    blurb:
      'n plain public keys → one x-only aggregate key, including the order-dependence, the all-identical-keys case, and every malformed-key rejection.',
  },
  {
    id: 'nonce_gen',
    title: 'Nonce generation',
    file: 'nonce_gen_vectors.json',
    blurb:
      'The exact two-nonce derivation, with and without a secret key to harden the randomness, and with an absent vs. empty message.',
  },
  {
    id: 'nonce_agg',
    title: 'Nonce aggregation',
    file: 'nonce_agg_vectors.json',
    blurb:
      'Both halves summed independently — including the case where a half cancels to the point at infinity and must serialize as 33 zero bytes.',
  },
  {
    id: 'sign_verify',
    title: 'Partial signing & verification',
    file: 'sign_verify_vectors.json',
    blurb:
      'Partial signatures byte-for-byte, plus the spec’s rejections: wrong signer, negated signature, out-of-range scalar, malformed nonce.',
  },
  {
    id: 'tweak',
    title: 'Tweaked key aggregation',
    file: 'tweak_vectors.json',
    blurb:
      'Plain and x-only tweaks applied to the aggregate key. Implemented for spec coverage; Taproot output assembly is a different lab.',
  },
  {
    id: 'det_sign',
    title: 'Deterministic signing',
    file: 'det_sign_vectors.json',
    blurb:
      'The two-signer variant where the last signer derives its nonce from the other side’s aggregate nonce instead of fresh randomness.',
  },
  {
    id: 'sig_agg',
    title: 'Signature aggregation',
    file: 'sig_agg_vectors.json',
    blurb:
      'Partial signatures summed into one 64-byte signature — and each result handed to a plain BIP-340 verifier, which accepts.',
  },
];

// ---------------------------------------------------------------- error matching

interface SpecError {
  type: string;
  signer?: number | null;
  contrib?: string;
  message?: string;
}

/** Does the thrown error match the spec's expectation for this case? */
function errorMatches(err: unknown, expected: SpecError): { ok: boolean; actual: string } {
  if (!(err instanceof Error)) return { ok: false, actual: `non-Error thrown: ${String(err)}` };
  if (expected.type === 'invalid_contribution') {
    if (!(err instanceof InvalidContributionError)) {
      return { ok: false, actual: `plain Error: ${err.message}` };
    }
    const ok =
      err.signer === (expected.signer ?? null) &&
      (expected.contrib === undefined || err.contrib === expected.contrib);
    return { ok, actual: `invalid_contribution(signer=${err.signer}, contrib=${err.contrib})` };
  }
  if (expected.type === 'value') {
    // The spec's "value" errors are precondition violations, distinct from a
    // misbehaving-party report. Matching on the class, not the English string.
    const ok = !(err instanceof InvalidContributionError);
    return { ok, actual: `value error: ${err.message}` };
  }
  return { ok: false, actual: `unknown expected error type: ${expected.type}` };
}

function expectThrow(
  fn: () => unknown,
  expected: SpecError,
): { pass: boolean; expectedText: string; actual: string } {
  const expectedText =
    expected.type === 'invalid_contribution'
      ? `invalid_contribution(signer=${expected.signer ?? null}, contrib=${expected.contrib})`
      : `value error: ${expected.message ?? '(any precondition failure)'}`;
  try {
    fn();
    return { pass: false, expectedText, actual: 'no error was thrown' };
  } catch (err) {
    const { ok, actual } = errorMatches(err, expected);
    return { pass: ok, expectedText, actual };
  }
}

const hexAll = (list: string[]): Uint8Array[] => list.map(hexToBytes);
const maybeHex = (v: string | null): Uint8Array | null => (v === null ? null : hexToBytes(v));

// ---------------------------------------------------------------- group runners

export function runKeyAggVectors(): KatResult[] {
  const out: KatResult[] = [];
  const X = hexAll(keyAggVectors.pubkeys);
  const T = hexAll(keyAggVectors.tweaks);

  keyAggVectors.valid_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const expected = tc.expected.toLowerCase();
    let actual: string;
    let pass: boolean;
    try {
      actual = bytesToHex(getXonlyPk(keyAgg(pubkeys)));
      pass = actual === expected;
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'key_agg',
      index,
      what: `aggregate keys [${tc.key_indices.join(', ')}] → one x-only key`,
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  keyAggVectors.error_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const tweaks = tc.tweak_indices.map((i) => T[i]);
    const r = expectThrow(
      () => keyAggAndTweak(pubkeys, tweaks, tc.is_xonly as boolean[]),
      tc.error as SpecError,
    );
    out.push({
      group: 'key_agg',
      index: keyAggVectors.valid_test_cases.length + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });
  return out;
}

export function runNonceGenVectors(): KatResult[] {
  return nonceGenVectors.test_cases.map((tc, index) => {
    let actual: string;
    let pass: boolean;
    const expected = `${tc.expected_secnonce.toLowerCase()} / ${tc.expected_pubnonce.toLowerCase()}`;
    try {
      const r = nonceGenInternal(
        hexToBytes(tc.rand_),
        maybeHex(tc.sk),
        hexToBytes(tc.pk),
        maybeHex(tc.aggpk),
        maybeHex(tc.msg),
        maybeHex(tc.extra_in),
      );
      actual = `${bytesToHex(r.secnonce)} / ${bytesToHex(r.pubnonce)}`;
      pass = actual === expected;
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    return {
      group: 'nonce_gen',
      index,
      what:
        tc.sk === null
          ? 'derive two nonces with no secret key to harden the randomness'
          : tc.msg === null
            ? 'derive two nonces with no message committed'
            : `derive two nonces (${hexToBytes(tc.msg).length}-byte message)`,
      kind: 'accept' as const,
      pass,
      expected,
      actual,
    };
  });
}

export function runNonceAggVectors(): KatResult[] {
  const out: KatResult[] = [];
  const P = hexAll(nonceAggVectors.pnonces);

  nonceAggVectors.valid_test_cases.forEach((tc, index) => {
    const expected = tc.expected.toLowerCase();
    let actual: string;
    let pass: boolean;
    try {
      actual = bytesToHex(nonceAgg(tc.pnonce_indices.map((i) => P[i])));
      pass = actual === expected;
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'nonce_agg',
      index,
      what:
        'comment' in tc && tc.comment
          ? tc.comment
          : `sum nonces [${tc.pnonce_indices.join(', ')}] half by half`,
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  nonceAggVectors.error_test_cases.forEach((tc, index) => {
    const r = expectThrow(
      () => nonceAgg(tc.pnonce_indices.map((i) => P[i])),
      tc.error as SpecError,
    );
    out.push({
      group: 'nonce_agg',
      index: nonceAggVectors.valid_test_cases.length + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });
  return out;
}

export function runSignVerifyVectors(): KatResult[] {
  const out: KatResult[] = [];
  const sk = hexToBytes(signVerifyVectors.sk);
  const X = hexAll(signVerifyVectors.pubkeys);
  const secnonces = hexAll(signVerifyVectors.secnonces);
  const pnonce = hexAll(signVerifyVectors.pnonces);
  const aggnonces = hexAll(signVerifyVectors.aggnonces);
  const msgs = hexAll(signVerifyVectors.msgs);

  // The vector file's own internal consistency claims, checked rather than assumed.
  out.push({
    group: 'sign_verify',
    index: -1,
    what: 'the vector file’s stated pubkey/nonce/aggnonce relationships hold',
    kind: 'accept',
    pass:
      bytesToHex(individualPubkey(sk)) === bytesToHex(X[0]) &&
      bytesToHex(nonceAgg([pnonce[0], pnonce[1], pnonce[2]])) === bytesToHex(aggnonces[0]) &&
      bytesToHex(nonceAgg([pnonce[0], pnonce[3]])) === bytesToHex(aggnonces[1]),
    expected: 'pubkeys[0] = IndividualPk(sk); aggnonces[0..1] = NonceAgg(...)',
    actual: 'recomputed from the vector inputs',
  });

  signVerifyVectors.valid_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const pubnonces = tc.nonce_indices.map((i) => pnonce[i]);
    const aggnonce = aggnonces[tc.aggnonce_index];
    const msg = msgs[tc.msg_index];
    const expected = tc.expected.toLowerCase();
    let actual: string;
    let pass: boolean;
    try {
      // NOTE: a real signer must never copy a secnonce. The spec's own harness
      // does it here so one fixed nonce can drive several vectors.
      const session: SessionContext = { aggnonce, pubkeys, msg };
      const { psig } = sign(secnonces[0].slice(), sk, session);
      const verified = partialSigVerify(
        hexToBytes(tc.expected),
        pubnonces,
        pubkeys,
        msg,
        tc.signer_index,
      );
      actual = bytesToHex(psig);
      pass =
        actual === expected &&
        verified &&
        bytesToHex(nonceAgg(pubnonces)) === bytesToHex(aggnonce);
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'sign_verify',
      index,
      what: tc.comment ?? `partial signature for signer ${tc.signer_index}, then verify it`,
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  signVerifyVectors.sign_error_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const session: SessionContext = {
      aggnonce: aggnonces[tc.aggnonce_index],
      pubkeys,
      msg: msgs[tc.msg_index],
    };
    const r = expectThrow(
      () => sign(secnonces[tc.secnonce_index].slice(), sk, session),
      tc.error as SpecError,
    );
    out.push({
      group: 'sign_verify',
      index: 100 + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });

  signVerifyVectors.verify_fail_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const pubnonces = tc.nonce_indices.map((i) => pnonce[i]);
    let accepted: boolean;
    try {
      accepted = partialSigVerify(
        hexToBytes(tc.sig),
        pubnonces,
        pubkeys,
        msgs[tc.msg_index],
        tc.signer_index,
      );
    } catch {
      accepted = false;
    }
    out.push({
      group: 'sign_verify',
      index: 200 + index,
      what: tc.comment,
      kind: 'reject',
      pass: !accepted,
      expected: 'partial-signature verification returns false',
      actual: accepted ? 'ACCEPTED (must not happen)' : 'rejected',
    });
  });

  signVerifyVectors.verify_error_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const pubnonces = tc.nonce_indices.map((i) => pnonce[i]);
    const r = expectThrow(
      () =>
        partialSigVerify(hexToBytes(tc.sig), pubnonces, pubkeys, msgs[tc.msg_index], tc.signer_index),
      tc.error as SpecError,
    );
    out.push({
      group: 'sign_verify',
      index: 300 + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });

  return out;
}

export function runTweakVectors(): KatResult[] {
  const out: KatResult[] = [];
  const sk = hexToBytes(tweakVectors.sk);
  const X = hexAll(tweakVectors.pubkeys);
  const secnonce = hexToBytes(tweakVectors.secnonce);
  const pnonce = hexAll(tweakVectors.pnonces);
  const aggnonce = hexToBytes(tweakVectors.aggnonce);
  const tweaks = hexAll(tweakVectors.tweaks);
  const msg = hexToBytes(tweakVectors.msg);

  tweakVectors.valid_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const pubnonces = tc.nonce_indices.map((i) => pnonce[i]);
    const tw = tc.tweak_indices.map((i) => tweaks[i]);
    const isXonly = tc.is_xonly as boolean[];
    const expected = tc.expected.toLowerCase();
    let actual: string;
    let pass: boolean;
    try {
      const session: SessionContext = { aggnonce, pubkeys, tweaks: tw, isXonly, msg };
      const { psig } = sign(secnonce.slice(), sk, session);
      actual = bytesToHex(psig);
      pass =
        actual === expected &&
        partialSigVerify(
          hexToBytes(tc.expected),
          pubnonces,
          pubkeys,
          msg,
          tc.signer_index,
          tw,
          isXonly,
        );
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'tweak',
      index,
      what: tc.comment ?? `partial signature under ${tw.length} tweak(s)`,
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  tweakVectors.error_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const session: SessionContext = {
      aggnonce,
      pubkeys,
      tweaks: tc.tweak_indices.map((i) => tweaks[i]),
      isXonly: tc.is_xonly as boolean[],
      msg,
    };
    const r = expectThrow(() => sign(secnonce.slice(), sk, session), tc.error as SpecError);
    out.push({
      group: 'tweak',
      index: tweakVectors.valid_test_cases.length + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });
  return out;
}

export function runDetSignVectors(): KatResult[] {
  const out: KatResult[] = [];
  const sk = hexToBytes(detSignVectors.sk);
  const X = hexAll(detSignVectors.pubkeys);
  const msgs = hexAll(detSignVectors.msgs);

  detSignVectors.valid_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const aggothernonce = hexToBytes(tc.aggothernonce);
    const tw = hexAll(tc.tweaks);
    const isXonly = tc.is_xonly as boolean[];
    const msg = msgs[tc.msg_index];
    const expected = tc.expected.map((e) => e.toLowerCase()).join(' / ');
    let actual: string;
    let pass: boolean;
    try {
      const { pubnonce, psig } = deterministicSign(
        sk,
        aggothernonce,
        pubkeys,
        msg,
        maybeHex(tc.rand),
        tw,
        isXonly,
      );
      actual = `${bytesToHex(pubnonce)} / ${bytesToHex(psig)}`;
      const session: SessionContext = {
        aggnonce: nonceAgg([aggothernonce, pubnonce]),
        pubkeys,
        tweaks: tw,
        isXonly,
        msg,
      };
      pass =
        actual === expected &&
        partialSigVerifyInternal(psig, pubnonce, pubkeys[tc.signer_index], session);
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'det_sign',
      index,
      what: tc.comment ?? 'derive a nonce from the other side’s aggregate nonce, then sign',
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  detSignVectors.error_test_cases.forEach((tc, index) => {
    const r = expectThrow(
      () =>
        deterministicSign(
          sk,
          hexToBytes(tc.aggothernonce),
          tc.key_indices.map((i) => X[i]),
          msgs[tc.msg_index],
          maybeHex(tc.rand),
          hexAll(tc.tweaks),
          tc.is_xonly as boolean[],
        ),
      tc.error as SpecError,
    );
    out.push({
      group: 'det_sign',
      index: detSignVectors.valid_test_cases.length + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });
  return out;
}

export function runSigAggVectors(): KatResult[] {
  const out: KatResult[] = [];
  const X = hexAll(sigAggVectors.pubkeys);
  const pnonce = hexAll(sigAggVectors.pnonces);
  const tweaks = hexAll(sigAggVectors.tweaks);
  const psigList = hexAll(sigAggVectors.psigs);
  const msg = hexToBytes(sigAggVectors.msg);

  sigAggVectors.valid_test_cases.forEach((tc, index) => {
    const pubkeys = tc.key_indices.map((i) => X[i]);
    const pubnonces = tc.nonce_indices.map((i) => pnonce[i]);
    const aggnonce = hexToBytes(tc.aggnonce);
    const tw = tc.tweak_indices.map((i) => tweaks[i]);
    const isXonly = tc.is_xonly as boolean[];
    const psigs = tc.psig_indices.map((i) => psigList[i]);
    const expected = tc.expected.toLowerCase();
    let actual: string;
    let pass: boolean;
    try {
      const session: SessionContext = { aggnonce, pubkeys, tweaks: tw, isXonly, msg };
      const { sig } = partialSigAgg(psigs, session);
      actual = bytesToHex(sig);
      const aggpk = getXonlyPk(keyAggAndTweak(pubkeys, tw, isXonly));
      // The headline claim, on the spec's own bytes: a stock BIP-340 verifier accepts.
      pass =
        actual === expected &&
        bytesToHex(nonceAgg(pubnonces)) === bytesToHex(aggnonce) &&
        nobleVerify(sig, msg, aggpk);
    } catch (err) {
      actual = `threw: ${(err as Error).message}`;
      pass = false;
    }
    out.push({
      group: 'sig_agg',
      index,
      what: `${psigs.length} partial signatures → one 64-byte signature that plain BIP-340 accepts`,
      kind: 'accept',
      pass,
      expected,
      actual,
    });
  });

  sigAggVectors.error_test_cases.forEach((tc, index) => {
    const session: SessionContext = {
      aggnonce: hexToBytes(tc.aggnonce),
      pubkeys: tc.key_indices.map((i) => X[i]),
      tweaks: tc.tweak_indices.map((i) => tweaks[i]),
      isXonly: tc.is_xonly as boolean[],
      msg,
    };
    const r = expectThrow(
      () => partialSigAgg(tc.psig_indices.map((i) => psigList[i]), session),
      tc.error as SpecError,
    );
    out.push({
      group: 'sig_agg',
      index: sigAggVectors.valid_test_cases.length + index,
      what: tc.comment,
      kind: 'reject',
      pass: r.pass,
      expected: r.expectedText,
      actual: r.actual,
    });
  });
  return out;
}

/** Every BIP-327 vector this lab runs, in spec order. */
export function runAllVectors(): KatResult[] {
  return [
    ...runKeyAggVectors(),
    ...runNonceGenVectors(),
    ...runNonceAggVectors(),
    ...runSignVerifyVectors(),
    ...runTweakVectors(),
    ...runDetSignVectors(),
    ...runSigAggVectors(),
  ];
}

/** Headline counts for the KAT panel and the README. */
export function katSummary(results: KatResult[] = runAllVectors()): {
  total: number;
  passed: number;
  failed: number;
  accept: number;
  reject: number;
} {
  return {
    total: results.length,
    passed: results.filter((r) => r.pass).length,
    failed: results.filter((r) => !r.pass).length,
    accept: results.filter((r) => r.kind === 'accept').length,
    reject: results.filter((r) => r.kind === 'reject').length,
  };
}
