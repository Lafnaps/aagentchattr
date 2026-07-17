# autonomy queue (M0+M1)

Durable, fail-closed, file-system task queue for unattended night work.
No server, no network, no imports from the live agentchattr modules: one
producer (the control plane) drops task cards through `enqueue`, one or more
workers claim them through the CLI. Everything is plain JSON files moved
atomically between state directories on one NTFS volume. The machine-readable
contract lives in `contract.json`; this file explains the semantics.

## CLI contract

```
python -m autonomy.queue_cli --root R init
python -m autonomy.queue_cli --root R enqueue  --card X:\abs\path\card.json
python -m autonomy.queue_cli --root R claim    --profile P --model M --worker W
python -m autonomy.queue_cli --root R peek-exact  --task-id T
python -m autonomy.queue_cli --root R list-exact
python -m autonomy.queue_cli --root R claim-exact --task-id T --expected-next-attempt N --expected-digest D --profile P --model M --worker W
python -m autonomy.queue_cli --root R quarantine-exact-payload --task-id T --worker W
python -m autonomy.queue_cli --root R complete --task-id T --worker W
python -m autonomy.queue_cli --root R complete-exact --task-id T --expected-attempt N --expected-digest D --worker W
python -m autonomy.queue_cli --root R fail     --task-id T --worker W [--reason ...]
python -m autonomy.queue_cli --root R fail-exact --task-id T --expected-attempt N --expected-digest D --worker W --disposition retry|final [--reason ...]
python -m autonomy.queue_cli --root R block    --task-id T --worker W --reason ...
python -m autonomy.queue_cli --root R block-exact --task-id T --expected-attempt N --expected-digest D --worker W --reason ...
python -m autonomy.queue_cli --root R requeue  --task-id T --worker W
python -m autonomy.queue_cli --root R requeue-exact --task-id T --expected-attempt N --expected-digest D --worker W
python -m autonomy.queue_cli --root R audit
```

Every invocation prints **exactly one JSON object to stdout** -- success and
failure alike (even argument errors). Exit codes:

- `0` success.
- `2` validation error or transition conflict (fail-closed refusal). This
  **includes `claim` finding no eligible work**, reported as
  `{"ok": false, "error": "nothing-to-claim", "claimed": null}` -- an empty
  poll is deliberately a non-success exit so a scheduler can never mistake
  it for a claim.
- `3` `audit` found an AUDIT_GAP, or an unrecoverable I/O failure.

## Layout (created by `init` under an explicit --root)

```
<root>\autonomy-root.json           marker; refused unless exactly
                                    {"version": 1, "name": "agentchattr-autonomy-queue"}
<root>\queue\<task_id>.json         claimable cards
<root>\in_progress\...              exactly-one-owner cards
<root>\done\ | failed\ | blocked\
<root>\attempts\<task_id>\a<N>\     one immutable working dir per claim attempt
<root>\events\<task_id>\<seq>.json  append-only per-task audit chain
<root>\exact\<task_id>.json         immutable exact-protocol admission marker
<root>\tmp\                         staging for atomic publishes (crash residue is inert)
```

Exactly one of the five state directories contains a task's card; `audit`
reports duplicates or a card missing for known events/attempts/exact markers
as AUDIT_GAP.

## Task card

Closed schema, duplicate JSON keys rejected, exact types only (`true` is not
`1`, `2.0` is not `2`) -- see `contract.json`. Key semantics:

- `payload_relpath` + `payload_sha256` pin the out-of-band payload. The
  relpath is relative to `allowed_root` and rejects absolute paths,
  empty/`.`/`..` segments, control characters, `<>:"|?*` (which also blocks
  drive letters and NTFS alternate data streams), and reserved device names.
  Every component of the resolved walk is lstat-checked: a symlink, junction,
  or any other reparse point anywhere on the path fails closed, backstopped
  by a realpath containment check. The payload must be a regular file of at
  most 4 MiB and its SHA-256 must match exactly -- verified **at enqueue and
  again immediately before a successful claim** (twice at claim: before the
  rename as the admission gate, and after winning it so a payload swapped
  in between still cannot survive; the loser is rolled back and quarantined).
- `max_attempts` accepts **only the exact ints 1 or 2** (default 2). Bools,
  floats, strings, 0, and anything above 2 are rejected.
- `attempt` must be exactly 0 at enqueue, is incremented durably by `claim`,
  and is preserved by `requeue`.
- `restart_safe` defaults to false; a card without the key is NOT
  restart-safe.
- A malformed card is never executed and never deleted: `claim` quarantines
  it to `blocked/` with a `block-malformed` event whenever the move is safely
  possible.

## Exact-CAS queue API

`card_authority_digest(card)` is the lowercase SHA-256 of canonical compact,
sorted-key ASCII JSON without a trailing newline for the normalized card
(including materialized defaults), excluding **only** mutable `attempt`.
`attempt` is bound separately, so a
view remains digest-stable across its intended attempt bump while either a
generation change or any authority-card change invalidates the CAS inputs.

`peek-exact` returns one task's `task_id`, state, current/next attempt,
digest, profile, model, payload verification result, and `worker`. For
`in_progress`, `worker` is the owner from the durable active claim; it is
`null` in every other state. In the executable states (`queue`,
`in_progress`) an unverifiable payload refuses the whole view fail-closed, so
a peek can never advertise executable work it did not verify; in the
non-executable states (`blocked`/`done`/`failed`) the view instead reports
`payload: {verified: false, error, path: null, sha256}`, so an operator can
inspect a card they just quarantined without the expected drift masking the
durable evidence. `list-exact` returns the same fields for queued tasks in
task-id order, therefore with `worker: null`. Each list item is individually
locked and verified, not a globally atomic snapshot. Both commands run the
same full semantic validator as exact mutations. A malformed queue name or
corrupt card/event/attempt/marker makes the authoritative read fail closed;
no partial list is returned. This all-or-nothing behavior is an intentional
head-of-line safety policy: dispatch must not silently skip corrupt queued
work. A payload-only verification failure on an otherwise semantically valid
queue card is deliberately different: `list-exact` exposes that entry with
`verified: false` and its refusal code instead of aborting, so one drifted
payload can never hide every healthy task. They never quarantine, move,
rewrite queue evidence, create an event, or issue a nonce (the task lock may
use its normal file under `tmp/`).

`claim-exact` names the task and requires the exact next attempt, digest,
profile, model, and worker. Under the existing per-task lock it verifies the
single state, normalized card, budget, digest, filters, and payload before
moving. Before its first exact state move it exclusively publishes
`exact/<task_id>.json`, a canonical, closed-schema, immutable marker binding
`task_id`, authority digest, `first_exact_attempt`, and `prior_event_seq`.
The last field is the immutable count of contiguous events already present
under the lock. Events through that boundary are supported marker-free legacy
history and must replay to `queue` at `first_exact_attempt - 1`; only the tail
after it is governed by exact protocol. This prevents later exact admission
from retroactively reinterpreting an earlier legacy quarantine/requeue, while
still making stripping exact metadata from the governed tail a detectable
downgrade. A matching marker plus the unchanged queue card at attempt
`first_exact_attempt - 1` is the admitted no-event response-loss window; retry
continues idempotently. An exact `block-payload` or `block-attempt-dir` at that
same boundary is canonical terminal evidence. A conflicting durable marker
fails semantic admission; a conflict observed during exclusive publication is
`exact-protocol-conflict`. Repeating the identical call after a completed
claim succeeds only when the card is already the same `in_progress`
incarnation and the exact claim event plus immutable `a<N>` directory match.
All other replays fail closed.

If a queued task's payload later drifts or disappears -- whether the task is
already marker-governed or still marker-free (the normal state of freshly
enqueued work before its first `claim-exact`) -- that card cannot be claimed,
and `audit` re-verifies every otherwise-valid queued card and reports
`exact_payload_unavailable` with its `task_id`, durable authority digest, and
next attempt instead of returning clean. The digest is the immutable marker
authority when a marker exists; for a marker-free card it is the authority
digest of the validated queue card written at enqueue (enqueue verified the
payload against that card before admission). The targeted
`quarantine-exact-payload --task-id T --worker W` command needs no cached view
or caller-supplied digest: under the task lock it derives authority and
generation solely from that validated durable evidence, verifies that the
payload is actually unavailable, then publishes the canonical exact
`block-payload` tail. For a still marker-free queued card it first publishes
the exact protocol marker (`first_exact_attempt = attempt + 1`) under the same
lock strictly before the state move, so a crash between the two leaves the
admitted idempotent response-loss window and the retry heals through the
marker-governed path. It never derives authority from the current payload
bytes. A healthy payload refuses `exact-payload-not-drifted` before any
marker is published; a marker-free card outside `queue` refuses
`exact-evidence-missing` and stays on the legacy verbs. An identical retry
after response loss accepts only that matching canonical blocked tail and
does not reread the payload. `claim-exact` on a still marker-free drifted
card refuses without quarantining; this command is the exact-protocol repair
path for that case.

The quarantine command is task-targeted, so corrupt history belonging to an
unrelated task cannot prevent recovery of the named valid task. Corruption in
the named task is never guessed through or repaired: the command refuses
without mutation, audit stays non-clean, and audit never labels the corrupt
task as repairable `exact_payload_unavailable` drift. `list-exact`
deliberately remains all-or-nothing fail-closed until every corrupt queued
history is resolved; only payload-only drift is exposed per-entry instead.

Once quarantined (and once the payload is restored byte-for-byte),
`requeue-exact --task-id T --expected-attempt N --expected-digest D
--worker W` is the exact blocked -> queue transition while retry budget
remains. Authority and ownership are the durable exact blocked tail -- the
terminal exact `block` or the exact `block-payload` quarantine event -- never
a caller assertion: the worker must equal that tail's worker
(`exact-worker-mismatch` otherwise) and the attempt/digest must match the
current card and marker authority. An exact `block-attempt-dir` tail is
**never** requeueable: its immutable collision directory `a<attempt+1>`
cannot be removed or reused, so a re-armed `claim-exact` would collide and
quarantine again forever. That tail refuses
`exact-attempt-dir-not-requeueable` before any mutation, for every worker;
the quarantine is terminal for the task identity and the safe recovery is a
new `task_id`. The payload must re-verify byte-exactly
first; a still-drifted payload refuses `exact-payload-not-restored` without
mutation. The published `requeue-exact` event preserves the attempt and binds
`attempt_dir` `a<attempt+1>` -- the re-armed next generation that the
subsequent `claim-exact` creates -- in move-then-event order, so a crash
between the two stays a visible AUDIT_GAP (`state_mismatch`) and the retry
fails closed rather than repairing it. An identical retry after response loss
accepts only the matching canonical `requeue-exact` queue tail -- refusing
every worker other than the durable owner -- and does not
reread the payload. Exhausted budget refuses `max-attempts-exhausted`; a
marker-free blocked task refuses `exact-evidence-missing` and stays on legacy
`requeue`; there is deliberately no exact requeue from `failed/` because an
exact `fail-final` only ever happens with the budget already exhausted. The
next `claim-exact` then uses `attempt + 1` with no-downgrade semantics
intact.

Before every exact mutation or replay, a single per-task semantic validator
under that same lock replays the **entire contiguous event chain**. It checks
legal `from/to` and attempt progression, retry/final and requeue policy,
current card state/attempt/authority, immutable marker consistency, exact
prefix boundary, `first_exact_attempt <= max_attempts`, owner continuity, and
the complete immutable attempt index. Normal claims require exactly `a1..aN`;
an exact `block-attempt-dir` additionally makes its next-generation collision
directory expected evidence. Missing, extra, non-directory, reparse, or
otherwise inconsistent evidence is `exact-evidence-invalid`; it is never
repaired and no fresh attempt is made. Every governed claim, exact pre-claim
quarantine, and `requeue-exact` after `prior_event_seq` must carry exact
evidence; a `requeue-exact` event that is marker-free, pre-boundary,
metadata-stripped, or over budget is invalid. Owner continuity is durable,
not response-local: every persisted `requeue-exact` event must immediately
follow an exact terminal `block` or exact `block-payload` tail (never a
`block-attempt-dir`) and must carry exactly that predecessor's worker.
Rewriting only the `worker` field of a stored requeue event therefore fails
closed as `exact-evidence-invalid` for every caller -- including the forged
worker -- and `audit` reports `exact_transition_inconsistency`
(`requeue-exact-worker-mismatch`, `requeue-exact-invalid-predecessor`, or
`requeue-exact-after-attempt-dir-quarantine`) instead of clean.

`complete-exact`, `fail-exact`, and `block-exact` require the expected
attempt, digest, and the worker recorded by the last exact claim. `fail-exact`
also requires the caller to predict `retry` or `final`; a mismatch is refused
before mutation and is recomputed before a replay may return success. An
identical call after response loss succeeds only when the already-terminal
state and **tail** exact event match; conflicting terminals are refused
(including a different reason on replay). Exact events add the closed pair
`authority_digest` + `attempt_dir` to the legacy event shape, permitted only
on exact claim/complete/fail-retry/fail-final/block and on exact pre-claim
`block-payload`/`block-attempt-dir`. For those two quarantine events,
`event.attempt` remains the current generation and `attempt_dir` binds the
attempted next `a<event.attempt+1>`; exact payload quarantine intentionally has
no such directory, while exact directory-collision quarantine preserves it as
evidence. `requeue-exact` events use the same next-generation binding
(`a<event.attempt+1>`, not yet existing) and always carry the exact pair.
Exact metadata on legacy requeue or `block-malformed` is malformed. There
is deliberately no queue nonce: a future
dispatch nonce belongs in tick-state intent, not the queue card or event.
Legacy `claim`, `complete`, `fail`, `block`, and `requeue` remain compatible
with marker-free legacy histories, including quarantine followed by operator
requeue before later exact admission. They run under the per-task lock and,
once history exists, through the full validator. After an exact marker exists,
every new legacy mutation refuses `exact-transition-required`, even if exact
event fields were removed or a worker field was rewritten. Missing,
malformed, illegal, or incomplete evidence refuses
`exact-evidence-invalid`; deleting/mangling/appending an event cannot
downgrade an exact task into a legacy one.

The marker is filesystem integrity evidence, not a cryptographic defence
against a process already able to coherently replace **all** task artifacts.
A same-identity writer rewriting the marker, card, entire event chain, and
attempt tree together is explicitly outside this threat model.

## Retry policy

`fail` is the **single supervisor retry path** from `in_progress`: it moves
the card back to `queue/` while `attempt < max_attempts` (`fail-retry`),
otherwise to `failed/` (`fail-final`). With the default `max_attempts = 2`
the second failure is final. Legacy `requeue` is the **operator-only** path
while a task is still marker-free and only from `blocked/` or `failed/` back to
`queue/` **while** `attempt < max_attempts`, always preserving `attempt` -- so
a permitted legacy requeue's next claim creates a fresh, never-reused
`a<N+1>` attempt dir and may later be admitted to exact protocol. Exact-marked
tasks remain on exact verbs and cannot append legacy requeue: their operator
path is `requeue-exact`, from `blocked/` back to `queue/` **while**
`attempt < max_attempts`, owned by the exact blocked tail and gated on
byte-exact payload restoration (see the exact-CAS section). Once the budget
is exhausted, both requeue verbs fail with
`max-attempts-exhausted`; an operator who deliberately wants another run must
enqueue a new `task_id`.

## Atomicity, ordering, and crash windows

- A state transition is ONE same-volume **no-overwrite** atomic rename of the
  card between state directories (Windows `os.rename` refuses existing
  targets natively; on POSIX a link+unlink pair is used, whose crash window
  leaves the card visible in both directories -- reported by `audit` as
  `duplicate_states`, never repaired). Parallel `claim`s therefore have
  exactly one winner and can never silently replace an existing card.
- Every state-changing command holds a fixed per-task cross-process OS file
  lock from its first authoritative card/state read through the move,
  attempt mutation, and event publication. This prevents a retry claim (or
  any other second transition) from interleaving between a move and its
  event. A process crash releases the kernel lock without repairing files,
  so the documented move/event `AUDIT_GAP` remains visible.
- Events are append-only, one file per seq (`events/<task>/<seq:06d>.json`).
  The next seq is `max(existing) + 1` -- never `len()+1` -- and the file is
  published by staging in `tmp/` and moving with an exclusive no-overwrite
  create, so **an existing seq file can never be replaced**; a collision
  rescans and retries, then fails closed.
- Claim order: validate card -> refuse an exhausted queued card
  (`attempt >= max_attempts`) without moving it, creating an attempt dir, or
  appending an event (legacy `claim` refuses `max-attempts-exhausted`; the
  exact verbs refuse that durable budget violation during semantic validation
  as `exact-evidence-invalid`, and audit reports it as
  `attempt_budget_violation`) -> verify payload (if a previously published exact marker
  governs an already-drifted queued payload, publish canonical exact
  `block-payload` instead of leaving a wedged clean queue card) -> for a first
  exact mutation publish the marker and its `prior_event_seq` boundary ->
  rename to `in_progress` ->
  re-verify payload -> exclusive `mkdir attempts/<task>/a<N>` (a pre-existing
  directory rolls an exact claim back and quarantines the card with canonical
  exact `block-attempt-dir`; unsafe/non-directory collision fails as I/O) ->
  rewrite card with the new attempt -> publish the
  claim event -> print the success JSON. The attempt dir exists before the
  card ever advertises the new attempt, and **the CLI's stdout is the only
  signal that a claim is executable** -- consumers must not act on the
  contents of `in_progress/` directly.
- Documented crash windows, all visible to `audit` and none auto-repaired:
  - after the rename, before the card rewrite -> `state_mismatch`;
  - after the mkdir, before the card rewrite -> `extra_attempt_dir`;
  - after the card rewrite, before the event -> `card_attempt_mismatch`;
  - POSIX link+unlink midpoint -> `duplicate_states`.
- Every state/events/attempts path component is validated against a closed
  name grammar and lstat-checked for symlink/junction/reparse points before
  any read or write. (The residual lstat-then-open TOCTOU requires a
  concurrent writer inside the queue root, which is outside the M0 threat
  model of a single-operator volume.)

## AUDIT_GAP detection (`audit --root R`)

`audit` first discovers task identities, acquires their per-task locks in
sorted order, and repeats discovery until it owns one stable locked snapshot.
It therefore cannot observe the normal move-before-event window of a live
mutation as a false gap. It then **semantically replays** each task's event chain
from `(queue, attempt=0)` -- enforcing contiguous seq from 1, closed event
schema with exact types and valid UTC timestamps, table-consistent
`from/to`, legal transition sequencing, and per-transition attempt
semantics -- then independently compares the replayed truth against the
exactly-one state card, the card's `attempt`, the immutable exact marker, and
its `prior_event_seq` legacy-prefix boundary, plus immutable attempt dirs and
their numbering. It also checks `first_exact_attempt <= max_attempts`. Any
divergence exits `3` with
`{"audit": "AUDIT_GAP", "gaps": [...]}`; it never repairs.

Detected kinds: `layout`, `unexpected_entry`, `duplicate_states`,
`orphan_events`, `orphan_attempts`, `malformed_card`, `malformed_event`,
`broken_seq`, `event_chain_too_long`, `illegal_transition`,
`from_to_mismatch`, `attempt_mismatch`, `state_mismatch`,
`attempt_without_events` (a queue card claiming attempts with no history),
`card_attempt_mismatch`, `missing_attempt_dir`, `extra_attempt_dir`,
`attempt_budget_violation` (a card/history exceeding its execution budget,
an exhausted card left in `queue/`, or an exhausted requeue event),
`card_authority_mismatch`, `exact_transition_inconsistency`,
`orphan_exact_protocol`, `malformed_exact_protocol`,
`exact_protocol_conflict`, `exact_protocol_missing`,
`exact_protocol_inconsistency`, and `exact_payload_unavailable` (an
otherwise-valid queued card -- marker-governed or still marker-free -- whose
payload cannot be re-verified; the gap carries the durable authority digest
and next attempt that the targeted quarantine command needs). Exact
marker checks bind the protocol even if
mutable event metadata is removed, while evidence at or before the recorded
legacy boundary is never retroactively treated as exact. Audit never invents
nonce evidence for legacy histories.

One deliberate exception: an unreadable card sitting in `blocked/` whose
final event is `block-malformed` is a *known quarantined state*, not a gap --
the quarantine itself is the audit trail.

## Fail-closed root and path rules

- `--root` must be an absolute, existing directory containing the exact
  closed-schema marker written by `init`; everything else is refused.
- `task_id` must match `^[a-z0-9][a-z0-9-]{0,63}$` (Windows reserved device
  names also rejected); anything resembling a path is rejected before any
  filesystem access.
- Cards, events, and the marker are parsed as strict UTF-8 with malformed
  UTF-8/JSON, duplicate keys, and NaN/Infinity rejected, plus a 1 MiB read
  cap; payload hashing is capped at 4 MiB. No read is unbounded.
- The CLI never touches live agentchattr data, processes, SVN, or any
  TradeStation working copy. It operates only under the given root plus the
  card-pinned `allowed_root` payload read.

## Scheduler/bootstrap trust boundary

- The dependency manifest always contains `autonomy/__init__.py`,
  `autonomy/boot_clock.py`, `autonomy/runner.py`, and
  `autonomy/supervisor_tick.py`. Every listed Python module is reviewed
  **trusted code** and part of the TCB; untrusted payloads are never admitted
  as Python dependencies. `autonomy/boot_clock.py` is both a required manifest
  path and a closure root, so an absent or drifted boot clock fails validation
  closed (scheduler: `manifest-required-entry-missing`; bootstrap:
  `manifest-missing-boot-clock`) before any Create or trusted runner
  execution, while an exact pinned one is compiled and loaded like every other
  dependency.
- The bootstrap validates exact paths, identities and SHA-256 pins, then loads
  ordinary `autonomy.*` imports from those verified bytes. Missing modules do
  not get an ordinary filesystem-import fallback.
- This finder and the scheduler's static closure scanner provide integrity,
  reproducibility, and defence-in-depth lint. They are **not an in-process
  capability sandbox**: trusted Python can use the standard library and OS
  APIs. A true hostile-code boundary would require a separately admitted
  low-privilege OS process and filesystem ACLs.
- `runner.py` exposes no public arm/context API. Its loader-injected private
  one-shot handoff catches accidental direct use and replay in a fresh runner
  process; it is explicitly not cryptographic provenance against code already
  executing in that interpreter.
- The currently admitted `supervisor_tick.py` is a deterministic readiness
  no-op. It does not claim queue work or touch processes, Task Scheduler,
  network, agentchattr state, SVN, or product files.

## Boot-clock producer (M4, isolated component)

`autonomy/boot_clock.py` is a stdlib-only, producer-only component. It is
deliberately **unintegrated**: nothing in the queue, runner, supervisor, or
scheduler consumes a reading yet, a reading is **not a cross-reboot ordering
guarantee**, and it grants **no live or deploy authority**. The rejected
clock-epoch integration architecture (seal_task, tick_core epoch propagation,
owner glue, scheduler epoch checks, residue policy) is **not implemented**.

- `WindowsBootClock().sample()` returns a frozen, closed `ClockReading` with
  `epoch` (exactly 32 lowercase hex chars) and `now_ns` (exact non-bool int
  in `0..MAX_NS`, `MAX_NS = 2**63 - 1`).
- The epoch source is exactly `ctypes.WinDLL("ntdll.dll")`'s
  `NtQuerySystemInformation` information class 90
  (SystemBootEnvironmentInformation) with a zeroed raw 32-byte buffer and
  length 32. A result is trusted only when the signed NTSTATUS is exactly 0
  AND ReturnLength is exactly 32 (the kernel returns STATUS_SUCCESS with a
  truncated 20-byte fill for input sizes 20..31, so the length check is
  load-bearing). An all-zero identifier is refused. The epoch is the raw
  identifier bytes as hex -- never a UUID/textual GUID conversion.
- `sample()` is query A -> `time.monotonic_ns()` -> query B and requires
  A == B, so a reading can never pair a time with an ambiguous boot
  identifier. Every refusal is a typed `BootClockError` with a stable code;
  there is no cache, wall clock, WMI, uptime subtraction, random token,
  registry, environment, or persisted-file fallback of any kind.
- Non-win32 platforms fail closed before any WinDLL access. There is no
  constructor/callable/epoch/reading injection surface; hermetic tests patch
  the module's private helpers only.

## Local evidence transport

`autonomy/evidence_transport.py` is a small, stdlib-only boundary primitive;
it does not send chat messages, use the network, or inspect live agentchattr
state. The constrained executor packs only an explicit, non-empty list of
regular files below its own source root. An authorized scribe verifies the
received bytes and may unpack them below a new target root. An independent
reviewer checks the same transported bytes and manifest rather than trusting
either role's description.

The library API is `pack(source_root, relative_paths) -> bytes`,
`verify(bundle) -> EvidenceManifest`, and
`unpack(bundle, absent_target_root) -> EvidenceManifest`. The matching CLI is:

```
python -m autonomy.evidence_transport pack --source-root V:\work\attempt result.json logs\gate.txt > evidence.jsonl
python -m autonomy.evidence_transport verify evidence.jsonl
python -m autonomy.evidence_transport unpack evidence.jsonl V:\review\received
```

Use a byte-preserving native stdout redirect (for example `cmd.exe` or
PowerShell 7+) for `pack`; `verify` and `unpack` also accept `-` for stdin.
Source and target roots must be absolute local paths. Transport paths use `/`
separators and are recorded in the explicit order supplied.

Schema v1 is canonical UTF-8-without-BOM JSONL with LF endings and strict
Base64. Each chunk and file has a SHA-256, while the bundle hash binds the
schema/version, chunk size, ordinal path list, per-file sizes, and per-file
hashes. Parsing rejects duplicate JSON keys, unknown fields, wrong types,
noncanonical bytes, missing/duplicate/reordered records, and trailing data.
Fixed pre-materialization limits are 1 MiB per chunk, 32 files, 4096 chunks
per file, 16 MiB per file, 32 MiB total payload, 512 UTF-8 bytes per relative
path, and 96 MiB per encoded bundle.

Paths fail closed on absolute/drive/UNC/device forms, empty or dot
components, `..`, control or Windows-reserved punctuation (including
`:`/ADS), reserved device names, trailing dot/space, case-fold collisions,
and file/parent collisions. Packing and unpacking reject symlink/reparse
ancestors and enforce real-path containment. `verify` has no filesystem side
effects. `unpack` verifies the complete bounded bundle first, writes and
flushes a unique sibling staging directory, then uses one native atomic
no-replace rename to an absent target. Existing or race-created targets are
never overwritten or removed, and failed staging is cleaned up.

## Tests

```
python -m unittest tests.test_autonomy_queue -v
python -m unittest tests.test_evidence_transport -v
```

Hermetic (temp directories only, no network): module-form CLI contract and
single-JSON-object output, parallel-claim uniqueness across real OS
processes, event seq collision (existing seq never replaced), full
transition matrix, retry/final failure for max_attempts 1 and 2, payload
missing/tampered/traversal/symlink/junction escapes (link tests skip only
where the platform cannot create links), pre-existing attempt dir
fail-closure, strict type/duplicate-key/timestamp validation, payload size
limit, no-overwrite transition collisions, and the full audit gap matrix
including simulated crash windows. Exact-CAS coverage includes canonical
digest bytes, read-only views, concurrent/replayed claims, topology ABA,
wrong bindings, conflicting terminal calls, max-attempt dispositions, and
semantic-evidence corruption: illegal prefixes, missing/corrupt attempt dirs,
missing/malformed claim events, legacy-tail downgrade attempts, and forbidden
exact metadata on requeue/quarantine events. Exact-protocol coverage also
includes marker response-loss replay, conflicting/malformed/removed markers,
stripped exact fields, rewritten workers, missing `a1`, authoritative
peek/list corruption refusal, legacy requeue refusal, and audit serialization
against the move-before-event window. Restart coverage also proves targeted
payload quarantine without a cached digest, response-loss replay, a clean
post-quarantine audit with unrelated healthy work listable, refusal on corrupt
target history, and durable in-progress worker visibility. Fix8 coverage adds
the marker-free queued drift matrix (audit gap with card-derived authority,
list-exact exposure without head-of-line loss, wrong-profile poll inertness,
targeted quarantine with marker publication, crash/response-loss replay,
wrong-worker refusal, corrupt-target refusal with targeted repair of an
unrelated task) and the `requeue-exact` matrix (budget-gated blocked -> queue
with restored-payload gate, tail-owner enforcement, CAS mismatch refusals,
legacy-downgrade refusal, exhausted/wrong-state/marker-free/corrupt-history
refusals, move-before-event crash visibility, idempotent replay, correct next
exact claim, and stripped-metadata downgrade detection). Fix9 coverage adds
the durable requeue-continuity matrix: an exact `block-attempt-dir`
quarantine refuses `requeue-exact` for every worker with zero mutation, a
hand-forged post-collision requeue/claim loop is rejected by the validator
and reported by audit instead of ever looking clean, and worker-only forgery
of a persisted `requeue-exact` event (after both a terminal exact `block`
and an exact `block-payload` restore/requeue) fails closed for the forged
and the original worker while canonical owner replay keeps succeeding.
