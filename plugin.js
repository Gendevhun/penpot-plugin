"use strict";
(() => {
  // src/precog-core.ts
  var POLICY_VERSION = "precog-local-mvp-1.0.0";
  var AUDIT_SCHEMA_VERSION = 1;
  var MAX_AUDIT_ENTRIES = 1e3;
  var ZERO_HASH = "0".repeat(64);
  var SIGNAL_CATALOG = {
    "phishing.reputation_suspicious": { category: "phishing", score: 38, confidence: 0.72 },
    "phishing.url_homoglyph": { category: "phishing", score: 42, confidence: 0.82 },
    "phishing.domain_known_bad": { category: "phishing", score: 72, confidence: 0.9 },
    "phishing.credential_harvest": { category: "phishing", score: 66, confidence: 0.88 },
    "malware.mime_mismatch": { category: "malware", score: 68, confidence: 0.86 },
    "impersonation.identity_mismatch": { category: "impersonation", score: 74, confidence: 0.84 },
    "privacy.sensitive_export": { category: "data_exposure", score: 64, confidence: 0.8 },
    "auth.session_anomaly": { category: "account_takeover", score: 58, confidence: 0.78 },
    "auth.new_device_downgrade": { category: "account_takeover", score: 52, confidence: 0.72 },
    "fraud.pattern_anomaly": { category: "fraud", score: 63, confidence: 0.77 },
    "unknown.signal": { category: "unknown", score: 30, confidence: 0.3 }
  };
  var PrecogError = class extends Error {
    code;
    constructor(code, message) {
      super(message);
      this.name = "PrecogError";
      this.code = code;
    }
  };
  var SOURCES = /* @__PURE__ */ new Set([
    "browser",
    "file",
    "call",
    "chat",
    "auth",
    "network",
    "device",
    "payment",
    "custom"
  ]);
  function randomId() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }
    return `local-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
  function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (value && typeof value === "object") {
      const record = value;
      return Object.fromEntries(
        Object.keys(record).sort().map((key) => [key, canonicalize(record[key])])
      );
    }
    return value;
  }
  function stableStringify(value) {
    return JSON.stringify(canonicalize(value));
  }
  async function sha256(value) {
    if (typeof crypto === "undefined" || !crypto.subtle || typeof TextEncoder === "undefined") {
      throw new PrecogError("CRYPTO_UNAVAILABLE", "Web Crypto nem \xE9rhet\u0151 el; hash-l\xE1nc nem k\xE9sz\xEDthet\u0151.");
    }
    const bytes = new TextEncoder().encode(typeof value === "string" ? value : stableStringify(value));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  function sanitizeEvent(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new PrecogError("INVALID_EVENT", "Az esem\xE9ny form\xE1tuma hib\xE1s.");
    }
    const raw = input;
    if (typeof raw.source !== "string" || !SOURCES.has(raw.source)) {
      throw new PrecogError("INVALID_SOURCE", "Ismeretlen esem\xE9nyforr\xE1s.");
    }
    const type = typeof raw.type === "string" ? raw.type.trim() : "";
    if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(type)) {
      throw new PrecogError("INVALID_EVENT_TYPE", "Az esem\xE9nyt\xEDpus nem biztons\xE1gos vagy \xE9rv\xE9nytelen.");
    }
    if (raw.signals !== void 0 && (!Array.isArray(raw.signals) || raw.signals.length > 16)) {
      throw new PrecogError("INVALID_SIGNALS", "Legfeljebb 16 struktur\xE1lt jel adhat\xF3 meg.");
    }
    const signals = [];
    for (const candidate of raw.signals ?? []) {
      if (typeof candidate !== "string") continue;
      const id = Object.hasOwn(SIGNAL_CATALOG, candidate) ? candidate : "unknown.signal";
      if (!signals.includes(id)) signals.push(id);
    }
    const suppliedTs = typeof raw.ts === "string" ? Date.parse(raw.ts) : NaN;
    const ts = Number.isFinite(suppliedTs) ? new Date(suppliedTs).toISOString() : (/* @__PURE__ */ new Date()).toISOString();
    return {
      id: randomId(),
      ts,
      source: raw.source,
      type,
      signals,
      demo: raw.demo === true,
      privacy: { sensitivity: "personal", rawDataAllowed: false }
    };
  }
  function aggregateScore(definitions) {
    const ordered = [...definitions].sort((a, b) => b.score - a.score);
    const weighted = ordered.reduce((sum, item, index) => {
      const factor = index === 0 ? 1 : index === 1 ? 0.25 : 0.15;
      return sum + item.score * factor;
    }, 0);
    return Math.min(100, Math.round(weighted));
  }
  function aggregateConfidence(definitions) {
    const missProbability = definitions.reduce((probability, item) => probability * (1 - item.confidence), 1);
    return Math.round((1 - missProbability) * 1e3) / 1e3;
  }
  function assessRisk(event) {
    const grouped = /* @__PURE__ */ new Map();
    for (const id of event.signals) {
      const category = SIGNAL_CATALOG[id].category;
      const group = grouped.get(category) ?? [];
      group.push(id);
      grouped.set(category, group);
    }
    const categories = [...grouped.entries()].map(([key, ids]) => {
      const defs = ids.map((id) => SIGNAL_CATALOG[id]);
      return {
        key,
        score: aggregateScore(defs),
        confidence: aggregateConfidence(defs),
        signals: ids
      };
    }).sort((a, b) => b.score - a.score);
    const definitions = event.signals.map((id) => SIGNAL_CATALOG[id]);
    return {
      eventId: event.id,
      overall: aggregateScore(definitions),
      confidence: aggregateConfidence(definitions),
      categories,
      modelVersion: "local-rules-1",
      rulesetVersion: POLICY_VERSION
    };
  }
  function decide(risk, eventId) {
    const score = risk.overall;
    const recommendedAction = score < 30 ? "allow" : score < 60 ? "warn" : score < 80 ? "challenge" : "block";
    const allowedActions = recommendedAction === "allow" ? ["allow"] : recommendedAction === "warn" ? ["warn", "allow"] : recommendedAction === "challenge" ? ["challenge", "block"] : ["block"];
    return {
      id: randomId(),
      eventId,
      risk,
      allowedActions,
      recommendedAction,
      requiresUserInteraction: recommendedAction !== "allow",
      policyVersion: POLICY_VERSION,
      explanationKeys: [`policy.range.${recommendedAction}`],
      externalEscalationAllowed: false
    };
  }
  function initialState() {
    return {
      schemaVersion: AUDIT_SCHEMA_VERSION,
      consent: { enabled: false, updatedAt: null },
      entries: []
    };
  }
  function entryCore(entry) {
    const { entryHash: _entryHash, ...core } = entry;
    return core;
  }
  async function verifyState(raw) {
    if (raw === null || raw === void 0) return initialState();
    if (typeof raw !== "string" || raw.length > 2e6) {
      throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat m\xE9rete vagy t\xEDpusa \xE9rv\xE9nytelen.");
    }
    let state;
    try {
      state = JSON.parse(raw);
    } catch {
      throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat nem olvashat\xF3 JSON.");
    }
    if (!state || state.schemaVersion !== AUDIT_SCHEMA_VERSION || !Array.isArray(state.entries) || !state.consent || typeof state.consent.enabled !== "boolean" || !(state.consent.updatedAt === null || typeof state.consent.updatedAt === "string") || state.entries.length > MAX_AUDIT_ENTRIES) {
      throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat s\xE9m\xE1ja hib\xE1s vagy t\xFAll\xE9pte a kapacit\xE1st.");
    }
    let previousHash = ZERO_HASH;
    for (let index = 0; index < state.entries.length; index += 1) {
      const entry = state.entries[index];
      if (!entry || entry.seq !== index + 1 || entry.previousHash !== previousHash || typeof entry.entryHash !== "string" || !/^[a-f0-9]{64}$/.test(entry.entryHash) || !Number.isFinite(entry.risk) || entry.risk < 0 || entry.risk > 100 || !Number.isFinite(entry.confidence) || entry.confidence < 0 || entry.confidence > 1 || typeof entry.eventDigest !== "string" || typeof entry.decisionDigest !== "string") {
        throw new PrecogError("AUDIT_INTEGRITY", `A hash-l\xE1nc szerkezete hib\xE1s a ${index + 1}. bejegyz\xE9sn\xE9l.`);
      }
      const expectedHash = await sha256(entryCore(entry));
      if (expectedHash !== entry.entryHash) {
        throw new PrecogError("AUDIT_INTEGRITY", `A hash-l\xE1nc m\xF3dos\xEDt\xE1st jelez a ${index + 1}. bejegyz\xE9sn\xE9l.`);
      }
      previousHash = entry.entryHash;
    }
    if (state.consent.enabled) {
      const last = state.entries.at(-1);
      if (!last || !last.consentEnabled || last.consentUpdatedAt !== state.consent.updatedAt) {
        throw new PrecogError("CONSENT_INTEGRITY", "Az akt\xEDv hozz\xE1j\xE1rul\xE1shoz nem tal\xE1lhat\xF3 \xE9rv\xE9nyes auditnyugta.");
      }
    }
    return state;
  }
  async function loadAuditSnapshot(store2) {
    const state = await verifyState(await store2.read());
    return {
      state,
      integrity: "ok",
      headHash: state.entries.at(-1)?.entryHash ?? ZERO_HASH
    };
  }
  async function assessAndAppend(store2, input, consentOverride) {
    const event = sanitizeEvent(input);
    const snapshot = await loadAuditSnapshot(store2);
    if (snapshot.state.entries.length >= MAX_AUDIT_ENTRIES) {
      throw new PrecogError("AUDIT_CAPACITY_REACHED", "A helyi napl\xF3 el\xE9rte az 1000 bejegyz\xE9ses MVP-korl\xE1tot.");
    }
    const risk = assessRisk(event);
    const decision = decide(risk, event.id);
    const previousHash = snapshot.headHash;
    const consent = consentOverride ?? snapshot.state.consent;
    const core = {
      seq: snapshot.state.entries.length + 1,
      ts: event.ts,
      source: event.source,
      eventType: event.type,
      eventDigest: await sha256(event),
      decisionDigest: await sha256(decision),
      category: risk.categories[0]?.key ?? "none",
      risk: risk.overall,
      confidence: risk.confidence,
      action: decision.recommendedAction,
      policyVersion: POLICY_VERSION,
      consentEnabled: consent.enabled,
      consentUpdatedAt: consent.updatedAt,
      demo: event.demo,
      previousHash
    };
    const entry = { ...core, entryHash: await sha256(core) };
    const state = {
      schemaVersion: AUDIT_SCHEMA_VERSION,
      consent,
      entries: [...snapshot.state.entries, entry]
    };
    await store2.write(stableStringify(state));
    return { event, risk, decision, entry, state };
  }
  async function updateConsent(store2, enabled) {
    const snapshot = await loadAuditSnapshot(store2);
    const updatedAt = (/* @__PURE__ */ new Date()).toISOString();
    try {
      const result = await assessAndAppend(
        store2,
        {
          source: "custom",
          type: enabled ? "precog.consent.enabled" : "precog.consent.disabled",
          signals: []
        },
        { enabled, updatedAt }
      );
      return { state: result.state, auditRecorded: true };
    } catch (error) {
      const precogError = error instanceof PrecogError ? error : null;
      if (!enabled && precogError?.code === "AUDIT_CAPACITY_REACHED") {
        const state = {
          ...snapshot.state,
          consent: { enabled: false, updatedAt }
        };
        await store2.write(stableStringify(state));
        return { state, auditRecorded: false };
      }
      throw error;
    }
  }

  // src/plugin.ts
  var STORAGE_KEY = "genesis.precog.local-mvp.v1";
  function getRoot() {
    const root = penpot.root;
    if (!root) throw new Error("Nincs megnyitott Penpot-tervf\xE1jl a helyi audit t\xE1rol\xE1s\xE1hoz.");
    return root;
  }
  var store = {
    read: () => getRoot().getPluginData(STORAGE_KEY) ?? null,
    write: (value) => getRoot().setPluginData(STORAGE_KEY, value)
  };
  var TEST_SCENARIOS = {
    "phishing-high": {
      label: "Adathal\xE1szat \u2013 magas kock\xE1zat",
      signals: ["phishing.domain_known_bad", "phishing.credential_harvest", "phishing.url_homoglyph"]
    },
    "malware-file": {
      label: "Gyan\xFAs f\xE1jl \u2013 MIME-elt\xE9r\xE9s",
      signals: ["malware.mime_mismatch"]
    },
    "privacy-export": {
      label: "\xC9rz\xE9keny adat kiexport\xE1l\xE1sa",
      signals: ["privacy.sensitive_export"]
    }
  };
  penpot.ui.open("D\xF6m\xF6sAiTech \u2013 helyi v\xE9delem", "plugin.html", {
    width: 420,
    height: 650
  });
  function send(type, payload = {}) {
    penpot.ui.sendMessage({ type, payload });
  }
  function describeError(error) {
    if (error instanceof Error) return error.message;
    return "Ismeretlen hiba t\xF6rt\xE9nt.";
  }
  async function sendState() {
    try {
      const snapshot = await loadAuditSnapshot(store);
      send("security-state", {
        enabled: snapshot.state.consent.enabled,
        consentUpdatedAt: snapshot.state.consent.updatedAt,
        integrity: "ok",
        count: snapshot.state.entries.length,
        headHash: snapshot.headHash,
        entries: snapshot.state.entries.slice(-12).reverse()
      });
    } catch (error) {
      send("security-state", {
        enabled: false,
        integrity: "error",
        count: 0,
        entries: [],
        error: describeError(error)
      });
    }
  }
  async function guardPluginOperation(type) {
    const snapshot = await loadAuditSnapshot(store);
    if (!snapshot.state.consent.enabled) return { allowed: true, monitored: false };
    const result = await assessAndAppend(store, {
      source: "custom",
      type,
      signals: []
    });
    await sendState();
    return {
      allowed: result.decision.recommendedAction !== "block",
      monitored: true
    };
  }
  async function handle(message) {
    const type = typeof message?.type === "string" ? message.type : "";
    const payload = message?.payload && typeof message.payload === "object" ? message.payload : {};
    try {
      switch (type) {
        case "get-state":
          await sendState();
          return;
        case "set-consent": {
          const enabled = payload.enabled === true;
          const result = await updateConsent(store, enabled);
          send("consent-result", {
            enabled: result.state.consent.enabled,
            auditRecorded: result.auditRecorded
          });
          await sendState();
          return;
        }
        case "test-incident": {
          const scenarioId = typeof payload.scenarioId === "string" ? payload.scenarioId : "";
          const scenario = TEST_SCENARIOS[scenarioId];
          if (!scenario) {
            send("error", { message: "Ismeretlen teszteset." });
            return;
          }
          const snapshot = await loadAuditSnapshot(store);
          if (!snapshot.state.consent.enabled) {
            send("error", { message: "El\u0151bb enged\xE9lyezd a helyi v\xE9delmet ehhez a Penpot-f\xE1jlhoz." });
            return;
          }
          const result = await assessAndAppend(store, {
            source: "custom",
            type: "precog.demo.incident",
            signals: scenario.signals,
            demo: true
          });
          send("incident-result", {
            label: scenario.label,
            risk: result.risk.overall,
            confidence: result.risk.confidence,
            category: result.risk.categories[0]?.key ?? "unknown",
            action: result.decision.recommendedAction,
            requiresUserInteraction: result.decision.requiresUserInteraction,
            logged: true,
            demo: true,
            entryHash: result.entry.entryHash,
            seq: result.entry.seq
          });
          await sendState();
          return;
        }
        case "get-selection": {
          const gate = await guardPluginOperation("penpot.selection.read");
          if (!gate.allowed) {
            send("error", { message: "A helyi policy letiltotta a m\u0171veletet." });
            return;
          }
          const selection = penpot.selection.map((shape) => ({ id: shape.id, name: shape.name }));
          send("selection", { selection, monitored: gate.monitored });
          return;
        }
        case "create-rect": {
          const gate = await guardPluginOperation("penpot.shape.create_rectangle");
          if (!gate.allowed) {
            send("error", { message: "A helyi policy letiltotta a m\u0171veletet." });
            return;
          }
          const rect = penpot.createRectangle();
          rect.name = "\xDAj t\xE9glalap";
          rect.x = 100;
          rect.y = 100;
          rect.resize(200, 150);
          rect.fills = [{ fillColor: "#4361ee" }];
          send("operation-result", {
            message: gate.monitored ? "T\xE9glalap l\xE9trehozva; a helyi policy enged\xE9lyezte \xE9s napl\xF3zta a m\u0171veletet." : "T\xE9glalap l\xE9trehozva; a helyi v\xE9delem jelenleg ki van kapcsolva."
          });
          return;
        }
        case "hello":
          send("operation-result", { message: "Hell\xF3, D\xF6m\xF6sAiTech!" });
          return;
        default:
          send("error", { message: "Ismeretlen plugin\xFCzenet." });
      }
    } catch (error) {
      send("error", { message: `A m\u0171velet biztons\xE1gi ellen\u0151rz\xE9se nem siker\xFClt: ${describeError(error)}` });
      await sendState();
    }
  }
  penpot.ui.onMessage((message) => {
    void handle(message);
  });
})();
