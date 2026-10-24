import { getHuntingProgress, HUNTING_PHASES } from "./hunting-progress.ts";
import assert from "node:assert/strict";
import test from "node:test";

const run = (status, extra = {}) => ({ status, events: [], result: null, ...extra });
const engineEvent = (stage, kind = "started", sequence = 1) => ({ stage, kind, sequence });
const storedEvent = (stage, kind = "started", sequence = 1) => ({
  kind,
  sequence,
  payload: { stage, kind, sequence },
});
const states = (value) => getHuntingProgress(value).map((phase) => phase.status);

test("new and queued hunts distinguish not started from queued without inventing progress", () => {
  assert.deepEqual(
    HUNTING_PHASES.map((phase) => phase.id),
    ["research", "design", "investigation", "verification"],
  );
  assert.deepEqual(states(null), ["idle", "idle", "idle", "idle"]);
  assert.deepEqual(states(run("queued")), ["pending", "pending", "pending", "pending"]);
  assert.deepEqual(states(run("cancelled")), ["pending", "pending", "pending", "pending"]);
});

test("live persisted completion and started events advance exactly the active phase", () => {
  const current = run("running", {
    events: [storedEvent("research", "research_completed"), storedEvent("design", "started", 2)],
  });
  assert.deepEqual(states(current), ["completed", "running", "pending", "pending"]);
  assert.deepEqual(states(run("designing")), ["completed", "running", "pending", "pending"]);
  assert.deepEqual(states(run("running")), ["running", "pending", "pending", "pending"]);
});

test("direct stored evidence collections and hunting aliases identify Splunk work", () => {
  const current = run("running", {
    events: [storedEvent("hunting", "stage_started"), { kind: "evidence_collection", payload: { collection: {} } }],
  });
  assert.deepEqual(states(current), ["completed", "completed", "running", "pending"]);
  assert.deepEqual(
    states(run("running", { events: [{ kind: "evidence_collection", payload: { collection: {} } }] })),
    states(current),
  );
});

test("exported flat engine events and investigate/verify aliases are supported", () => {
  assert.deepEqual(states(run("running", { result: { events: [engineEvent("investigate")] } })), [
    "completed",
    "completed",
    "running",
    "pending",
  ]);
  assert.deepEqual(states(run("running", { result: { stage: "verify", events: [] } })), [
    "completed",
    "completed",
    "completed",
    "running",
  ]);
});

test("a final data gap is not displayed as four green completed phases", () => {
  const current = run("insufficient_data", { result: { stage: "verification", events: [] } });
  assert.deepEqual(states(current), ["completed", "completed", "completed", "insufficient_data"]);
  assert.equal(getHuntingProgress(current)[3].statusLabel, "자료 부족");
  assert.deepEqual(states(run("completed", { result: { stage: "verification", events: [] } })), [
    "completed",
    "completed",
    "completed",
    "completed",
  ]);
});

test("failure stops only the reached phase and leaves subsequent phases pending", () => {
  for (const [terminal, expected, label] of [
    ["failed", "failed", "실패"],
    ["model_error", "failed", "모델 오류"],
    ["cancelled", "cancelled", "중지"],
    ["budget_exhausted", "interrupted", "한도 도달"],
    ["interrupted", "interrupted", "중단"],
  ]) {
    const current = run(terminal, { events: [storedEvent("design")] });
    assert.deepEqual(states(current), ["completed", expected, "pending", "pending"], terminal);
    assert.equal(getHuntingProgress(current)[1].statusLabel, label, terminal);
  }
});

test("best-effort partial verification does not imply investigation or final phase completion", () => {
  for (const terminal of ["failed", "model_error", "cancelled", "budget_exhausted", "interrupted"]) {
    const current = run(terminal, {
      events: [
        storedEvent("research", "research_completed"),
        storedEvent("design", "design_completed", 2),
        storedEvent("hunting", "stage_started", 3),
        storedEvent("verification", "partial_verification", 4),
      ],
      result: {
        stage: "investigation",
        verification: { status: "completed", summary: "부분 근거 검증" },
        events: [engineEvent("verification", "partial_verification")],
      },
    });
    const progress = getHuntingProgress(current);
    assert.equal(progress[0].status, "completed", terminal);
    assert.equal(progress[1].status, "completed", terminal);
    assert.ok(["failed", "cancelled", "interrupted"].includes(progress[2].status), terminal);
    assert.equal(progress[3].status, "pending", terminal);
    assert.equal(progress[3].statusLabel, "부분 판정", terminal);
  }
});

test("nonempty invalid research or design output is not evidence of phase completion", () => {
  assert.deepEqual(
    states(
      run("failed", {
        result: { stage: "research", research: { summary: "검증 실패 자료", sources: [{}] }, events: [] },
      }),
    ),
    ["failed", "pending", "pending", "pending"],
  );
  assert.deepEqual(
    states(
      run("failed", {
        result: { stage: "design", research: { summary: "보존 자료" }, design: { stages: [{}] }, events: [] },
      }),
    ),
    ["completed", "failed", "pending", "pending"],
  );
});

test("a cancellation after a saved completion does not invent a later started phase", () => {
  const current = run("cancelled", { events: [storedEvent("research", "research_completed")] });
  assert.deepEqual(states(current), ["completed", "pending", "pending", "pending"]);
});

test("unknown terminal states and missing evidence do not manufacture completion", () => {
  assert.deepEqual(states(run("completed")), ["pending", "pending", "pending", "pending"]);
  assert.deepEqual(states(run("future_status", { result: { stage: "future_stage", events: [] } })), [
    "pending",
    "pending",
    "pending",
    "pending",
  ]);
  assert.deepEqual(states(run("constructor", { result: { stage: "toString", events: [] } })), [
    "pending",
    "pending",
    "pending",
    "pending",
  ]);
});
