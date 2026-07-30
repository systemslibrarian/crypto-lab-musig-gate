# MuSig Gate: What Would Make This a 10/10 Teaching Demo

## Bottom line

This is already an exceptional **cryptography demo**. The protocol is real, the attacks are real, the intermediate values are inspectable, the BIP-327 vectors run live, and the final signature is checked by two independent verifiers. Very few educational demos reach this level of technical honesty.

What keeps it from being a 10/10 **teaching experience** is not missing cryptography. It is that the learner has to assemble the curriculum for themselves.

The page currently says, in effect, “Here are five excellent exhibits.” A 10/10 version would say, “Here is the question you are going to answer; predict what happens, run the experiment, explain the result, and prove you can transfer the idea.”

**Current estimate: 8.5/10 overall**

| Dimension | Current | Why |
| --- | ---: | --- |
| Cryptographic correctness | 10/10 | Real secp256k1, BIP-327 KATs, independent verification, honest reductions |
| Technical depth | 10/10 | Key aggregation, nonce control, Wagner, ROS, malformed inputs, attribution |
| Interactivity | 9/10 | Real controls and attacks, not canned animation |
| Accessibility and robustness | 9.5/10 | Strong semantics, keyboard flow, contrast, mobile and axe coverage |
| Narrative coherence | 7.5/10 | Five tabs are peers; their causal relationship is mostly left implicit |
| Learning design | 7.5/10 | Most checks happen after the reveal and test recognition rather than prediction or transfer |

The path to 10/10 is therefore **editing, sequencing, and scaffolding**, not adding another attack or more equations.

## What the learner should leave knowing

The demo should optimize for four durable outcomes. A learner who finishes should be able to say, without looking at the page:

1. **MuSig2 turns an n-of-n signing group into one ordinary BIP-340 public key and one ordinary 64-byte Schnorr signature.** An outside verifier cannot infer the number of signers from those outputs.
2. **Plainly summing public keys is unsafe.** A signer who chooses last can cancel the honest keys. Hash-derived key coefficients bind every contribution to the complete key list and defeat that rogue-key construction.
3. **One nonce per signer is unsafe under concurrent signing.** A last mover can steer a plain nonce sum. MuSig2 uses two nonces and derives `b` from the aggregate nonce, key, and message, making the attack target depend on the attacker's own choice.
4. **MuSig2 is n-of-n, not t-of-n.** Every signer is required; threshold signing is the job of FROST.

Everything else, including the second-key shortcut, F_127 plot, Wagner parameters, ROS algebra, malformed encodings, and vector files, should support those outcomes rather than compete with them.

## The central teaching problem

The intended causal story is strong:

```text
One key + one signature is useful
        |
        v
Naive key aggregation is broken by rogue keys
        |
        v
Key coefficients repair key aggregation
        |
        v
Naive one-nonce signing is broken by nonce control
        |
        v
Two nonces plus b repair concurrent signing
        |
        v
The result is accepted by an ordinary BIP-340 verifier
```

The interface presents this as five equal tabs:

`Signing Session | Key Aggregation | Rogue Key Attack | Why Two Nonces | BIP-327 Vectors`

That makes the learner decide whether these are alternatives, prerequisites, chapters, or reference material. The code and README know the relationship; the interface should make it explicit.

## Priority 0: Build one guided learning path

Add a visible **Guided tour** mode while preserving the tabs as free-exploration deep links.

Recommended sequence:

1. **The promise:** three signers produce one key and one signature.
2. **Predict:** can an ordinary verifier tell that a group signed?
3. **Run:** step through one stable three-signer session.
4. **Break the obvious key rule:** predict and run the rogue-key attack against `Q = ΣP_i`.
5. **Repair the key rule:** run the same attack against `Q = Σa_iP_i`.
6. **Break the obvious nonce rule:** predict and steer `R = ΣR_i`.
7. **Repair the nonce rule:** run the same move against `R = R_1 + bR_2`.
8. **Return to the result:** perform the blind group-versus-single-signer challenge.
9. **Exit check:** explain the two defenses and the n-of-n limitation.

Each stop should show a short progress label such as **2 of 8: Break naive key aggregation**, plus one **Continue** action that moves to the next relevant state even when it crosses a tab.

This is the single highest-impact change because it turns five strong exhibits into one lesson.

## Priority 1: Make prediction happen before computation

The existing learner checks are good, but most appear after the demo has already supplied the answer. That tests recognition. The stronger pattern is:

> **Predict → Run → Observe → Explain → Transfer**

### Rogue-key prediction

Before either attack button, ask:

> Two honest signers publish `P_1` and `P_2`. An attacker publishes last. Which rule can the attacker manipulate into a key it owns?

- `Q = P_1 + P_2 + P_attacker`
- `Q = a_1P_1 + a_2P_2 + a_3P_attacker`
- Both
- Neither

Record the answer without immediately grading it. After both experiments, return to the prediction and explain why it was right or wrong.

### Nonce prediction

Before nonce steering, ask:

> If the attacker publishes last, can it choose a contribution that makes a plain sum land on a target point?

Then, before the two-nonce attempt:

> What changes when the multiplier `b` is computed from the nonce bytes the attacker just submitted?

### Session prediction

Move the indistinguishability question before the blind comparison. Let the learner commit to an answer, inspect both signatures, guess which is the group signature, and then reveal.

## Priority 2: Reduce the default cognitive load

The nonce panel currently contains three escalating lessons in one long surface:

1. Last-mover nonce steering.
2. Wagner's reduced-width generalized birthday forgery.
3. The full-width ROS forgery.

All three are valuable, but only the first is necessary to understand why MuSig2 has two nonces. Make the default lesson end after the one-nonce/two-nonce comparison and learner explanation.

Place Wagner and ROS under a clearly named expansion:

> **Advanced: turn nonce control into a full forgery**

Inside it, lead with one comparison table:

| Attack | Concurrent sessions | Reduced parameter? | What it needs | Why two nonces stop this route |
| --- | ---: | --- | --- | --- |
| Wagner | 4 in this demo | Challenge width only | A fixed k-list target | `b` makes the target depend on candidate nonces |
| ROS | 256 | No | A constant right-hand side | `b` makes the right-hand side move |

This preserves the research-grade material without making every learner process it before reaching the core conclusion.

Similarly:

- Keep the glossary collapsed, but show only the term needed by the current stage beside that stage.
- Keep full 32/33/64-byte values available, but show short values by default with **Inspect bytes** disclosures.
- Treat the all-keys-identical sentinel and second-key coefficient shortcut as **spec details**, not primary concepts.
- Present the vector panel as **Implementation evidence**, visually separate from the teaching path.

## Priority 3: Make causality visible, not just the values

The collapse diagram communicates cardinality very well: many things become one thing. It does not yet communicate the two security transformations strongly enough.

At the relevant stage, change the visual labels from generic inputs to the operation being performed:

```text
P_1        P_2        P_3
 |          |          |
x a_1      x a_2      x a_3
 |          |          |
a_1P_1 + a_2P_2 + a_3P_3  ->  Q
```

For nonces:

```text
R_11 + R_21 + R_31  ->  R_1
R_12 + R_22 + R_32  ->  R_2

b = H(aggregate nonce || Q || message)
R = R_1 + bR_2
```

The crucial animation or highlight is not “more hex appeared.” It is “the attacker's contribution changed the hash input, which changed the coefficient, which moved the result.”

For the two-nonce attack table, label the loop explicitly:

1. Attacker guesses or uses the current `b`.
2. Attacker chooses nonce bytes intended to hit the target.
3. Protocol hashes those submitted bytes and derives a different `b`.
4. The aggregate nonce misses the target.

Highlight the changed `b` and changed result in each row. This is the conceptual heart of the second defense.

## Priority 4: Add bridges between exhibits

Every panel should finish by answering two questions:

- **What did this establish?**
- **What question does it create next?**

Suggested bridges:

- Session step 2: “The coefficients are not cosmetic. Next, try the attack they prevent.”
- Key aggregation: “You verified the formula. Now let a malicious signer choose last.”
- Rogue-key attack: “Key setup is safe, but signing also aggregates fresh nonces. Can those be manipulated?”
- One-nonce attack: “Controlling `R` is the capability; Wagner and ROS show how concurrency turns it into forgery.”
- Vectors: “These cases establish conformance to BIP-327, not a general proof that this implementation is production-safe.”

Use action labels that name the conceptual transition, such as **Break naive key aggregation**, rather than generic navigation labels.

## Priority 5: Add one real transfer task

The current checks mostly ask the learner to select an explanation that has just appeared in nearby prose. Add a final scenario that changes the surface details:

> A custody team wants any 2 of 3 devices to approve a payment. They also want the on-chain spend to look like one signer. Should they use this MuSig2 setup as shown?

Expected answer:

> No. This MuSig2 setup is 3-of-3. It provides signature and key aggregation, not a quorum. Use a threshold protocol such as FROST for 2-of-3.

Then ask:

> A three-member group uses MuSig2 correctly. What can a chain observer learn from its key-path signature alone?

Expected answer:

> The observer sees an ordinary BIP-340 key and signature, not the signer count or group membership. Participants and network observers may still have off-chain information.

Finally ask the learner to match defense to threat:

| Threat | Defense |
| --- | --- |
| Last signer cancels honest public keys | Per-key coefficients bound to the full key list |
| Concurrent-session nonce manipulation | Two nonces combined with hash-derived `b` |
| One signer disappears | No defense in MuSig2; n-of-n signing fails |
| Secret nonce is reused | Operational nonce lifecycle; not solved merely by aggregation |

This verifies transfer and prevents the most dangerous misconception: treating MuSig2 as generic threshold multisig.

## First-screen and visual hierarchy

The first desktop viewport is polished, but it primarily asks the learner to read. The title, long proposition, “Why it matters” block, and five tabs arrive before a concrete task.

Improve the first screen by giving it one dominant action:

> **Run the 3-signer experiment**

Pair it with a compact promise:

> You will produce one ordinary signature, break two naive designs, and explain the two fixes.

The current detailed hero copy can remain, but the guided action should be visually dominant. The five exhibits should read as the lesson map, with the active stop and completed stops visible, rather than five unrelated destinations.

Do not add more decorative UI. The current visual system is restrained and appropriate for a technical lab. The needed visual change is stronger instructional hierarchy.

## Recommended implementation order

### Phase 1: Highest return

1. Add the guided-tour progress model and cross-tab **Continue** actions.
2. Move the rogue-key, nonce-control, and indistinguishability questions before their reveals.
3. Put Wagner and ROS behind an **Advanced** disclosure by default.
4. Add the final transfer task covering n-of-n versus threshold.

### Phase 2: Clarify the mechanisms

1. Annotate key chips as `a_iP_i`, not only `P_i`.
2. Add a two-line nonce dependency diagram showing `aggnonce -> b -> R`.
3. Make the two-nonce attempt visually highlight the moving hash input, coefficient, and target miss.
4. Add one-sentence bridges between panels.

### Phase 3: Polish and evidence

1. Summarize vectors first: accepted, rejected, and total passing counts.
2. Feature three meaningful vector cases: malformed key, out-of-range partial signature, and infinity handling.
3. Add “Copy value” controls only where learners are expected to compare bytes.
4. Add a **Start over** action that resets the complete guided lesson, not only one panel.

## Where the changes belong

| Area | Likely owner |
| --- | --- |
| Guided path, progress, tab transitions | `src/main.ts`, `index.html` |
| Prediction and blind comparison ordering | `src/ui/sessionPanel.ts` |
| Coefficient operation in the collapse visual | `src/ui/sessionPanel.ts`, `src/ui/keyaggPanel.ts` |
| Pre-attack prediction and causal debrief | `src/ui/roguePanel.ts` |
| Core-versus-advanced structure and moving-target visual | `src/ui/noncePanel.ts` |
| Summary and featured conformance cases | `src/ui/vectorsPanel.ts` |
| Reusable prediction/progress components | `src/ui/dom.ts` |
| Guided-tour and transfer-task coverage | `e2e/flows.spec.ts`, `e2e/a11y.spec.ts` |

## Definition of 10/10

The demo is a 10/10 teaching experience when a first-time learner can complete it without external explanation and the interface provides evidence that they can:

- Predict that naive public-key summation is vulnerable before seeing the attack.
- Explain why the accepted rogue signature indicts key setup, not the BIP-340 verifier.
- Predict why a last mover can steer a plain nonce sum.
- Explain the circular dependency created by `b = H(aggnonce || Q || m)` in their own choice or words.
- State that the output is one ordinary BIP-340 key and signature and that signer count is not encoded in either.
- Distinguish n-of-n MuSig2 from t-of-n threshold signing.
- Separate the core lesson from the advanced Wagner and ROS evidence.
- Complete the primary journey in roughly 8-12 minutes, with advanced material optional.

Suggested product metrics:

- At least 80% of test learners can correctly match both attacks to both defenses after one run.
- At least 80% reject MuSig2-as-shown for a 2-of-3 requirement.
- At least 80% can explain the accepted rogue signature without blaming the verifier.
- Median guided completion time stays under 12 minutes.
- No primary step requires expanding a glossary or reading raw hex to understand the conclusion.

## What not to add

- Do not add another attack to the primary path.
- Do not add more raw intermediate values by default.
- Do not turn the vector suite into a sixth conceptual lesson.
- Do not imply that an attack missing for a few rounds is itself a security proof.
- Do not blur MuSig2, FROST, DKG, Taproot transaction assembly, or nonce-reuse recovery into one demo.

The lab already has enough substance for a 10/10. The final step is to make the learner's thinking as carefully orchestrated as the cryptography.