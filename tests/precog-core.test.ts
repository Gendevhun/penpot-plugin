import assert from "node:assert/strict";
import test from "node:test";
import {
  assessAndAppend,
  loadAuditSnapshot,
  PrecogError,
  sanitizeEvent,
  updateConsent,
  type AuditStore,
} from "../src/precog-core.ts";

function memoryStore(): AuditStore & { value: string | null } {
  return {
    value: null,
    read() { return this.value; },
    write(value) { this.value = value; },
  };
}

test("a privacy guard kizárja a nyers URL-t és tetszőleges kontextusmezőket", () => {
  const event = sanitizeEvent({
    source: "browser",
    type: "url.open",
    signals: ["phishing.reputation_suspicious"],
    context: { url: "https://private.example/path?token=secret", pageText: "private content" },
    rawDataAllowed: true,
  });
  const serialized = JSON.stringify(event);
  assert.equal(event.privacy.rawDataAllowed, false);
  assert.equal(serialized.includes("private.example"), false);
  assert.equal(serialized.includes("secret"), false);
  assert.equal(serialized.includes("private content"), false);
});

test("a magas, többjelű adathalászati teszteset blokkolási policy-döntést ad, eszkaláció nélkül", async () => {
  const store = memoryStore();
  const result = await assessAndAppend(store, {
    source: "custom",
    type: "precog.demo.incident",
    signals: ["phishing.domain_known_bad", "phishing.credential_harvest", "phishing.url_homoglyph"],
    demo: true,
  });
  assert.ok(result.risk.overall >= 80);
  assert.equal(result.decision.recommendedAction, "block");
  assert.equal(result.decision.externalEscalationAllowed, false);
  assert.equal(result.decision.allowedActions.includes("escalate" as never), false);
  assert.equal(result.entry.demo, true);
});

test("egy közepes kockázatú jel kihívást ad, az ismeretlen jel pedig nem lesz csendes allow", async () => {
  const store = memoryStore();
  const malware = await assessAndAppend(store, {
    source: "file",
    type: "file.receive",
    signals: ["malware.mime_mismatch"],
  });
  assert.equal(malware.decision.recommendedAction, "challenge");

  const unknown = await assessAndAppend(store, {
    source: "custom",
    type: "custom.unknown_signal",
    signals: ["unrecognized.detector.signal"],
  });
  assert.equal(unknown.risk.overall, 30);
  assert.equal(unknown.decision.recommendedAction, "warn");
});

test("consent is explicit and the local incident entry is persisted with a verified chain", async () => {
  const store = memoryStore();
  assert.equal((await loadAuditSnapshot(store)).state.consent.enabled, false);
  const enabled = await updateConsent(store, true);
  assert.equal(enabled.auditRecorded, true);
  assert.equal(enabled.state.consent.enabled, true);

  await assessAndAppend(store, {
    source: "custom",
    type: "precog.demo.incident",
    signals: ["privacy.sensitive_export"],
    demo: true,
  });
  const snapshot = await loadAuditSnapshot(store);
  assert.equal(snapshot.integrity, "ok");
  assert.equal(snapshot.state.entries.length, 2);
  assert.equal(snapshot.state.entries[1].eventType, "precog.demo.incident");
  assert.equal(snapshot.state.entries[1].demo, true);
  assert.equal(snapshot.state.entries[1].consentEnabled, true);
});

test("a changed audit record is detected before further processing", async () => {
  const store = memoryStore();
  await assessAndAppend(store, {
    source: "custom",
    type: "penpot.shape.create_rectangle",
    signals: [],
  });
  const state = JSON.parse(store.value as string);
  state.entries[0].risk = 99;
  store.value = JSON.stringify(state);
  await assert.rejects(
    loadAuditSnapshot(store),
    (error: unknown) => error instanceof PrecogError && error.code === "AUDIT_INTEGRITY",
  );
});

test("invalid raw event types are rejected", () => {
  assert.throws(
    () => sanitizeEvent({ source: "custom", type: "email person@example.com", signals: [] }),
    (error: unknown) => error instanceof PrecogError && error.code === "INVALID_EVENT_TYPE",
  );
});
