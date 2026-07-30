# MuSig Gate

**MuSig2 · BIP-327** — n signers aggregate their public keys into one key and their nonces into one nonce, producing a single Schnorr signature indistinguishable from a lone signer's.

## What It Is

An interactive, browser-only lab for **MuSig2** as standardized in **[BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)**, over **secp256k1**, producing signatures verifiable by a plain **[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)** Schnorr verifier.

The problem it solves: an n-of-n multisig wallet normally has to publish n public keys and collect n signatures. That is expensive to store and verify, and it leaks the group's structure to anyone reading the chain. MuSig2 replaces all of it with **one key and one signature** — while remaining an interactive protocol in which every signer's secret key stays with that signer.

The exact primitives, all hand-rolled in `src/musig/` so every intermediate value is inspectable:

- **Key aggregation** — `Q = Σ a_i·P_i`, where `a_i = H("KeyAgg coefficient", L ‖ P_i)` and `L = H("KeyAgg list", P_1 ‖ … ‖ P_u)`. The coefficients are what defeat the rogue-key attack.
- **Two-round nonces** — each signer commits **two** nonces; halves aggregate independently and combine as `R = R_1 + b·R_2` with `b = H("MuSig/noncecoef", aggnonce ‖ Q ‖ m)`. The second nonce is what defeats the Wagner/ROS attacks on single-nonce two-round schemes.
- **Partial signatures** — `s_i = k_i1 + b·k_i2 + e·a_i·d_i (mod n)`, each independently verifiable so a bad contribution is **attributable** to a signer.
- **Aggregation** — `Σ s_i`, yielding `R.x ‖ s`: an ordinary 64-byte BIP-340 signature under the 32-byte aggregate key.

Group arithmetic (point add/multiply, field square root, scalar inversion) comes from **[@noble/curves](https://github.com/paulmillr/noble-curves)** — audited, and deliberately not the teaching subject. BIP-327 itself is implemented here.

Two things are deliberately run at reduced scale, each labelled as such in the page, because the honest alternative was to describe them in prose:

- **A drawable group.** `y² = x³ + 7` over **F_127** — the secp256k1 equation, same group law, 127 elements instead of 2^256 — so key aggregation can be *plotted* as real points and real additions. This is not the smooth textbook curve, which is the equation over the reals and a different object from the finite group cryptography happens in.
- **A truncated challenge.** Wagner's k-list forgery (below) needs a birthday search, so the challenge hash is cut to 21–30 bits. The algorithm is unmodified and the forgery genuinely verifies; at the real 256-bit width the same k-tree needs on the order of 2^85 operations. Every finished signature is checked twice: once by a hand-rolled BIP-340 verifier that reports its stage pipeline, and once by `@noble/curves`' own `schnorr.verify`. The two must agree, and a disagreement is surfaced as a failure rather than swallowed.

**Security model.** Honest-but-curious is not the threat model here: two exhibits hand the learner a real adversarial capability and let them use it. Secret keys and nonces are generated per session with WebCrypto, live only in tab memory, and are never persisted or transmitted. There is no backend.

**Not production crypto — a teaching demo.** The arithmetic is real and matches the specification's own test vectors, but it uses ordinary JavaScript `BigInt` and is **not constant-time**. It does nothing to solve the hardest operational problem in MuSig2, which is guaranteeing a secret nonce is used at most once across process restarts. For real signing, use an audited implementation such as [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

## Exhibits

1. **Signing Session** — one real MuSig2 session, stepped through six stages. A collapse diagram shows n public keys becoming 1, n nonce pairs becoming 1 nonce, and n partial signatures becoming 1 signature, with every coefficient, challenge and scalar shown at the stage that computes it. Choose 2–5 signers, type the message, toggle BIP-327 KeySort and watch the aggregate key move. Each signer's partial is checked in the group as well as the scalar field — `s_i·G` against `(R_i1 + b·R_i2)^± + e·a_i·g′·P_i`, compared byte-for-byte — and the secret scalars can be revealed so the equation is checkable by hand. The final stage hands the 64 bytes to a plain BIP-340 verifier. Break-it controls corrupt a single bit of one partial signature (the aggregator names the culprit) and attempt to sign with one signer absent (MuSig2 is n-of-n). A collapsed glossary introduces every term the page uses.

   The tab closes with **"One of these was signed by a group. Which one?"** — the headline claim put as a question rather than a statement. Two signatures over the same message sit side by side: one is this session's aggregate, the other comes from `@noble/curves`' ordinary single-signer `schnorr.sign`, and which slot is which is a WebCrypto coin flip. Guess, then reveal, then compare the two on every observable property — all of which read *identical*. It is equally clear about the limit: this hides the group from whoever reads the finished signature, not from a participant or a network observer.
2. **Key Aggregation** — the coefficients in the foreground. `L`, the second-key shortcut, every `a_i`, and an independently recomputed `Σ a_i·P_i` compared byte-for-byte against `Q`. Reverse the key order, apply KeySort, or make every key identical to exercise the all-keys-equal sentinel, and see the naive `Σ P_i` aggregate side by side with the BIP-327 one.

   The tab closes by **drawing it**: all 126 affine points of `y² = x³ + 7` over F_127, with each input key marked, an arrow to where its coefficient sent it, and a path stepping through the running totals to `Q` — alongside the naive `Σ P_i` path landing somewhere else entirely. Real points, real additions, and a text alternative carrying the same facts.
3. **Rogue Key Attack** — the break that killed naive multisig, run for real. Under naive aggregation the attacker publishes `P_rogue = t·G − ΣP_honest`, signs alone, and **the genuine BIP-340 verifier accepts** — shown as an alarm, not a success. The identical attack against BIP-327 runs the attacker's fixed-point search round by round and misses every time. A third control lets you supply your own rogue key and target secret and submit them to either rule.
4. **Why Two Nonces** — pick a target aggregate nonce. Against one nonce per signer, the attacker hits it *exactly*, first try, with one subtraction — and therefore chooses the challenge. Against BIP-327's two nonces, the same move misses every round, with the real `b` derived from the bytes the attacker just published.

   Then it goes further and **actually forges a signature**. Four concurrent sessions against an honest signer, Wagner's generalised-birthday algorithm over four lists, and out comes a valid signature on a message the honest signer never saw — from four sessions, five signatures. Everything is real secp256k1 (real keys, hash-derived key-aggregation coefficients so the key setup is *not* the flaw, a signing oracle that never reuses a nonce, a real verifier); only the challenge width is reduced. Running the identical attack against two nonces shows why it dies: the k-tree needs a fixed target, and every candidate nonce assignment produces a different one.
5. **BIP-327 Vectors** — all **56** official BIP-327 known-answer cases from all seven vector files, executed in the browser on load, each expandable to expected-vs-actual. Includes the specification's malformed-input cases, which must be *rejected* for the right reason.

## When to Use It

Use MuSig2 when:

- **Every** listed signer must sign, and you want the on-chain result to look like a single signer — smaller, cheaper, and private about the group's structure.
- You are building Bitcoin Taproot spends (BIP-340/341) and want a key-path spend for a group.
- Signers can run two communication rounds and each keep custody of their own key.

Do **NOT** use MuSig2 when:

- **You need a t-of-n quorum.** MuSig2 is n-of-n; every signer is mandatory. Losing one key means losing the funds. Use FROST — see [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/).
- **You need a public audit trail of who signed.** The whole point is that the signer set is unrecoverable from the signature. Record it elsewhere, out of band.
- **You cannot guarantee single use of a secret nonce.** A signer that replays a nonce across two different messages leaks its private key by elementary algebra. If a signer's storage can roll back, use the deterministic-signing variant or don't use a two-round scheme.
- **You need non-interactive aggregation** across parties who never talk. That is a different primitive — see [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) for BLS.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-musig-gate/>**

In the browser you can: step a real 2-to-5-signer session from fresh keys to one 64-byte signature; watch the key, nonce and signature collapses happen one stage at a time; verify the aggregate signature with a plain BIP-340 verifier and an independent library verifier; try to pick the group's signature out of a blind pair against a lone signer's and discover you cannot; corrupt one partial signature and see the culprit named; attempt to sign with a signer missing; mount a rogue-key attack that a real verifier accepts, then watch the same attack fail against BIP-327; steer a single-nonce aggregate onto a chosen target and watch the two-nonce version refuse; and run all 56 BIP-327 vectors live.

Deep links: `#session`, `#keyagg`, `#rogue`, `#nonce`, `#vectors`.

## What Can Go Wrong

- **Rogue keys.** Aggregating by plain summation lets the last signer to publish own the group key outright. Demonstrated end to end in exhibit 3; prevented by the key-aggregation coefficients.
- **A single nonce per signer.** Makes the aggregate nonce, and therefore the challenge, a value the last signer chooses — and that is enough to forge. Exhibit 4 runs **Wagner's generalised-birthday algorithm** ([Drijvers et al., IEEE S&P 2019](https://eprint.iacr.org/2018/417)) over four concurrent sessions and produces a real forged signature at reduced challenge width, then shows the same attack failing against two nonces. The polynomial-time ROS attack ([Benhamouda et al., 2020](https://eprint.iacr.org/2020/945)) breaks the same schemes without any birthday search but needs ~256 concurrent sessions, so it is named and not implemented.
- **Nonce reuse.** Signing two different messages with the same secret nonce reveals the private key. `sign()` here zeroes the secret nonce as it consumes it, so a second call fails loudly instead of leaking. The key-recovery algebra itself is demonstrated in [crypto-lab-schnorr-forge](https://systemslibrarian.github.io/crypto-lab-schnorr-forge/).
- **Key-list order.** `KeyAgg` is order-dependent — the same keys in a different order give a different aggregate key, and a group that disagrees on order derives different keys and cannot sign. BIP-327 defines `KeySort` for exactly this; the toggle in exhibit 1 makes the difference visible.
- **Malformed contributions.** Keys off the curve, keys with `x ≥ p`, nonces with a bad prefix byte, partial signatures `≥ n`, aggregate nonces that are not points. All fail closed, and all name the offending party — the spec insists a bad contribution be attributable, not merely fatal.
- **Legitimate degenerate cases.** An aggregate nonce half can cancel to the point at infinity (serialized as 33 zero bytes), and `R_1 + b·R_2` can itself be infinity, which the spec handles with a defined `R = G` fallback. Both are implemented and covered by vectors rather than crashed on.
- **A missing signer.** n-of-n means the absent signer's `e·a_i·d_i` term is simply not in `Σ s_i`, so verification fails. This is a property, not a bug — but it is a real operational risk if you wanted a quorum.

## Real-World Usage

- **Bitcoin Taproot (BIP-340/341/342).** MuSig2 is the standard way for a group to produce a key-path Taproot spend that is indistinguishable from a single-signer spend. BIP-327 exists to make independent wallet implementations interoperate.
- **Wallet and custody software.** Implemented in `libsecp256k1`'s `musig` module, and in wallets and coordination libraries built on it.
- **Lightning and channel constructions**, where reducing multi-party signatures to one signature reduces on-chain footprint.
- **Cross-organisation signing** where the participants specifically do not want the number of approvers visible on a public ledger.

BIP-327 supersedes the original MuSig2 paper's parameterisation for Bitcoin use and pins the exact hash tags, encodings and tweaking rules — which is why this lab tests against its vectors rather than against a paper.

## How to Run Locally

```bash
npm ci
npm run dev        # http://localhost:5173/crypto-lab-musig-gate/
npm test           # 242 unit tests, including the 56 BIP-327 spec KATs
npm run build      # tsc --noEmit && vite build
npm run preview    # serve the production build (the a11y gate serves it on port 4276)
npm run test:a11y  # what CI gates on: axe (both themes) + flows on Chromium desktop & mobile
npm run test:axe   # just the axe accessibility gate
npm run test:e2e   # just the Chromium flows
npm run test:e2e:all  # every engine: Chromium, mobile viewport, Firefox, WebKit
```

Requires Node 22+. `npm run test:a11y` needs the Playwright Chromium browser once (`npx playwright install chromium`); `npm run test:e2e:all` additionally needs `firefox webkit`.

## Related Demos

- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — MuSig2 is n-of-n; **the quorum case IS frost-threshold**. If you need t-of-n, you need FROST, not this.
- [crypto-lab-schnorr-forge](https://systemslibrarian.github.io/crypto-lab-schnorr-forge/) — plain BIP-340 Schnorr keygen, signing and the nonce-reuse key-recovery attack. This lab builds on it and does not re-teach it.
- [crypto-lab-dkg-gate](https://systemslibrarian.github.io/crypto-lab-dkg-gate/) — distributed key generation. Here each signer generates its own key independently; no DKG is involved.
- [crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — BLS signature aggregation. A different primitive over pairing-friendly curves, with different trade-offs.
- [crypto-lab-bitcoin-script](https://systemslibrarian.github.io/crypto-lab-bitcoin-script/) — Taproot transaction assembly and spending paths. Key tweaking is implemented here for spec-vector coverage but is not an exhibit.

## Build & Verify

**242 unit tests (Vitest), including 56 official BIP-327 known-answer cases** — 30 that must be accepted, 26 that must be rejected — plus **138 end-to-end tests (Playwright)** across four browser engines. All pass.

Spec vectors, verbatim from [bitcoin/bips · bip-0327/vectors](https://github.com/bitcoin/bips/tree/master/bip-0327/vectors):

| File | Cases | Covers |
| --- | --- | --- |
| `src/musig/vectors/key_agg_vectors.json` | 9 | key aggregation, order dependence, all-identical keys, malformed keys, bad tweaks |
| `src/musig/vectors/nonce_gen_vectors.json` | 4 | the two-nonce derivation, with/without secret-key hardening, absent vs. empty message |
| `src/musig/vectors/nonce_agg_vectors.json` | 5 | independent half summation, infinity encoding, malformed nonces |
| `src/musig/vectors/sign_verify_vectors.json` | 18 | partial signatures byte-for-byte, wrong signer, negated signature, out-of-range scalar |
| `src/musig/vectors/tweak_vectors.json` | 6 | plain and x-only tweaks applied to the aggregate key |
| `src/musig/vectors/det_sign_vectors.json` | 9 | deterministic signing for the last signer |
| `src/musig/vectors/sig_agg_vectors.json` | 5 | partial signatures → one 64-byte signature **that a plain BIP-340 verifier accepts** |

The same runners (`src/musig/vectors.ts`) drive both the Vitest suite and exhibit 5's live table, so a green table in the browser and a green CI run are the same claim.

**End-to-end (Playwright):** 34 functional flows across **four engines** — Chromium desktop, a Pixel 5 viewport, Firefox and WebKit — assert what the unit suite structurally cannot — that each exhibit renders its result rather than throwing, that alarm-versus-pass semantics actually reach the DOM (a successful forgery must render as `.verdict-alarm`, never `.verdict-pass`), that stepping reveals more of the *same* session rather than resampling it, that the blind pair really is indistinguishable, that a corrupted partial marks exactly one signer, that a malformed rogue key is refused before signing, that the theme toggle persists across a reload, that there is exactly one `<h1>` and one banner landmark, that arrow keys move between tabs, that the scripture line appears verbatim exactly once, and that nothing overflows horizontally at 320px. The Wagner forgery has its own flows: it must render as `.verdict-alarm`, `Σ e_j` must match `e*` exactly, and the two-nonce attempt must produce a distinct target for every probe. Every flow also asserts zero uncaught page errors and zero console errors.

Two workflows, for one reason: `deploy.yml` must stay byte-for-byte identical across the fleet and it installs only Chromium, so Firefox and WebKit cannot run inside it. `.github/workflows/e2e.yml` installs all three engines and runs the full matrix on every push and pull request, while `deploy.yml`'s gate step runs axe plus the Chromium flows. The Chromium projects therefore run in both places, deliberately.

Beyond the KATs, the unit suite covers: full 2-, 3-, 4- and 5-signer round trips verified by two independent verifiers; the algebraic identity `s_i = k_i1 + b·k_i2 + e·a_i·d_i` checked per signer; `Σ s_i` equal to the signature's `s`; secnonce consumption (a second `sign()` throws); refusal to sign with a mismatched key, an out-of-range key, or for a key list the signer is not in; rejection of a negated partial, a wrong-signer partial, and an out-of-range partial; single-bit tamper detection with correct attribution; the n-of-n boundary; the infinity-fallback and empty-message edge cases; the naive rogue-key attack **succeeding**; the BIP-327 rogue-key attack **failing**; single-nonce target-hitting **succeeding**; and two-nonce target-hitting **failing**. The Wagner module is tested on the unusual requirement that an attack must *succeed*: the forged signature verifies, the honest signer provably never saw the forged message, no nonce was reused (its oracle throws on reuse, so a nonce-reuse key leak cannot be masquerading as the k-sum), and `Σ e_j = e*` over the integers rather than merely modulo 2^bits — plus soundness of the k-tree itself, which must return `null` rather than an inexact answer. The drawable group is tested on the group axioms (closure, associativity, inverses, identity), its stated order of 127, and that its generator enumerates all 127 elements — if any of those failed, the picture would be a lie. The lone-signer comparison is tested both ways: indistinguishable in shape for 2–5 signers, and *not* interchangeable in substance (neither signature verifies under the other's key), with the coin flip shown to reach both slots.

**Accessibility gate:** `@axe-core/playwright` scans the production build for WCAG 2.1 A/AA violations in **both** themes, driving all five exhibits into their post-interaction states first — every step revealed, both attacks run in both modes, the malformed-input rejection path, the tamper and missing-signer failures, and every disclosure and learner check opened. Zero violations required.

Colour choices are checked rather than eyeballed: every text/background pair in `src/style.css` was contrast-computed against AA, verdict tints are explicit colours rather than `color-mix()` so their ratios are verifiable, muted text lowers lightness instead of using `opacity`, and state is always icon + word + colour so it survives greyscale and deuteranopia.

`.github/workflows/deploy.yml` runs unit tests → build (typecheck included) → the full Playwright suite (axe gate *and* functional flows), and only then deploys, so a broken build, a functional regression, or an accessibility regression never ships.

## Performance

Everything runs client-side with JavaScript `BigInt` arithmetic, so scalar multiplication dominates everything else. Measured on an Apple-silicon laptop, Chromium:

| Operation | Time |
| --- | --- |
| Full 5-signer session + complete panel render | **~76 ms** |
| Same session measured in isolation, Node (no DOM) | ~207 ms for 5 signers, ~59 ms for 2 |
| All 56 BIP-327 vectors + table render | **~224 ms** |
| Wagner forgery, 27-bit challenge, 4 lists of 2,048 | **~420 ms** (~8,200 point additions) |
| Wagner forgery, 24-bit challenge | ~290 ms |
| The drawable group: 126 points + aggregation + plot | under 5 ms |

A 5-signer session performs roughly 40 scalar multiplications (10 nonce points, 5 key-aggregation contributions, 5 partial-signature self-checks, 5 partial verifications at 3 each, plus two full verifications), which is why the cost scales visibly with the signer count and why the Node figure — which repeats the whole protocol on the same signer set without any render caching — is the higher one. Sub-quarter-second is well inside "feels instant" for a click, which is why exhibit 5 runs the entire vector suite on every page load rather than shipping a cached result.

None of this arithmetic is constant-time and **no timing property should be inferred from these numbers** — they describe interactive responsiveness, not side-channel resistance.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
