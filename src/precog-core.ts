export const POLICY_VERSION = "precog-local-mvp-1.0.0";
export const AUDIT_SCHEMA_VERSION = 1;
export const MAX_AUDIT_ENTRIES = 1_000;
export const ZERO_HASH = "0".repeat(64);

export const SIGNAL_CATALOG = {
  "phishing.reputation_suspicious": { category: "phishing", score: 38, confidence: 0.72 },
  "phishing.url_homoglyph": { category: "phishing", score: 42, confidence: 0.82 },
  "phishing.domain_known_bad": { category: "phishing", score: 72, confidence: 0.90 },
  "phishing.credential_harvest": { category: "phishing", score: 66, confidence: 0.88 },
  "malware.mime_mismatch": { category: "malware", score: 68, confidence: 0.86 },
  "impersonation.identity_mismatch": { category: "impersonation", score: 74, confidence: 0.84 },
  "privacy.sensitive_export": { category: "data_exposure", score: 64, confidence: 0.80 },
  "auth.session_anomaly": { category: "account_takeover", score: 58, confidence: 0.78 },
  "auth.new_device_downgrade": { category: "account_takeover", score: 52, confidence: 0.72 },
  "fraud.pattern_anomaly": { category: "fraud", score: 63, confidence: 0.77 },
  "unknown.signal": { category: "unknown", score: 30, confidence: 0.30 },
} as const;

export type SignalId = keyof typeof SIGNAL_CATALOG;
export type RiskCategory = (typeof SIGNAL_CATALOG)[SignalId]["category"];
export type EventSource = "browser" | "file" | "call" | "chat" | "auth" | "network" | "device" | "payment" | "custom";
export type PolicyAction = "allow" | "warn" | "challenge" | "block";

export interface PrecogEvent {
  id: string;
  ts: string;
  source: EventSource;
  type: string;
  signals: SignalId[];
  demo: boolean;
  privacy: {
    sensitivity: "personal";
    rawDataAllowed: false;
  };
}

export interface RiskCategoryAssessment {
  key: RiskCategory;
  score: number;
  confidence: number;
  signals: SignalId[];
}

export interface RiskAssessment {
  eventId: string;
  overall: number;
  confidence: number;
  categories: RiskCategoryAssessment[];
  modelVersion: string;
  rulesetVersion: string;
}

export interface PrecogDecision {
  id: string;
  eventId: string;
  risk: RiskAssessment;
  allowedActions: PolicyAction[];
  recommendedAction: PolicyAction;
  requiresUserInteraction: boolean;
  policyVersion: string;
  explanationKeys: string[];
  externalEscalationAllowed: false;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  source: EventSource;
  eventType: string;
  eventDigest: string;
  decisionDigest: string;
  category: RiskCategory | "none";
  risk: number;
  confidence: number;
  action: PolicyAction;
  policyVersion: string;
  consentEnabled: boolean;
  consentUpdatedAt: string | null;
  demo: boolean;
  previousHash: string;
  entryHash: string;
}

export interface PersistedState {
  schemaVersion: 1;
  consent: {
    enabled: boolean;
    updatedAt: string | null;
  };
  entries: AuditEntry[];
}

export interface AuditStore {
  read(): string | null | undefined | Promise<string | null | undefined>;
  write(value: string): void | Promise<void>;
}

export interface AuditSnapshot {
  state: PersistedState;
  integrity: "ok";
  headHash: string;
}

export class PrecogError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PrecogError";
    this.code = code;
  }
}

const SOURCES = new Set<EventSource>([
  "browser", "file", "call", "chat", "auth", "network", "device", "payment", "custom",
]);

function randomId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `local-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record).sort().map((key) => [key, canonicalize(record[key])]),
    );
  }
  return value;
}

export function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

async function sha256(value: unknown): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle || typeof TextEncoder === "undefined") {
    throw new PrecogError("CRYPTO_UNAVAILABLE", "Web Crypto nem érhető el; hash-lánc nem készíthető.");
  }
  const bytes = new TextEncoder().encode(typeof value === "string" ? value : stableStringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Strictly allowlists the event envelope. Raw message, URL, document and identity fields are never copied. */
export function sanitizeEvent(input: unknown): PrecogEvent {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new PrecogError("INVALID_EVENT", "Az esemény formátuma hibás.");
  }
  const raw = input as Record<string, unknown>;
  if (typeof raw.source !== "string" || !SOURCES.has(raw.source as EventSource)) {
    throw new PrecogError("INVALID_SOURCE", "Ismeretlen eseményforrás.");
  }
  const type = typeof raw.type === "string" ? raw.type.trim() : "";
  if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(type)) {
    throw new PrecogError("INVALID_EVENT_TYPE", "Az eseménytípus nem biztonságos vagy érvénytelen.");
  }
  if (raw.signals !== undefined && (!Array.isArray(raw.signals) || raw.signals.length > 16)) {
    throw new PrecogError("INVALID_SIGNALS", "Legfeljebb 16 strukturált jel adható meg.");
  }

  const signals: SignalId[] = [];
  for (const candidate of (raw.signals ?? []) as unknown[]) {
    if (typeof candidate !== "string") continue;
    const id = Object.hasOwn(SIGNAL_CATALOG, candidate) ? candidate as SignalId : "unknown.signal";
    if (!signals.includes(id)) signals.push(id);
  }

  const suppliedTs = typeof raw.ts === "string" ? Date.parse(raw.ts) : NaN;
  const ts = Number.isFinite(suppliedTs) ? new Date(suppliedTs).toISOString() : new Date().toISOString();

  return {
    id: randomId(),
    ts,
    source: raw.source as EventSource,
    type,
    signals,
    demo: raw.demo === true,
    privacy: { sensitivity: "personal", rawDataAllowed: false },
  };
}

function aggregateScore(definitions: Array<(typeof SIGNAL_CATALOG)[SignalId]>): number {
  const ordered = [...definitions].sort((a, b) => b.score - a.score);
  const weighted = ordered.reduce((sum, item, index) => {
    const factor = index === 0 ? 1 : index === 1 ? 0.25 : 0.15;
    return sum + item.score * factor;
  }, 0);
  return Math.min(100, Math.round(weighted));
}

function aggregateConfidence(definitions: Array<(typeof SIGNAL_CATALOG)[SignalId]>): number {
  const missProbability = definitions.reduce((probability, item) => probability * (1 - item.confidence), 1);
  return Math.round((1 - missProbability) * 1_000) / 1_000;
}

export function assessRisk(event: PrecogEvent): RiskAssessment {
  const grouped = new Map<RiskCategory, SignalId[]>();
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
      signals: ids,
    };
  }).sort((a, b) => b.score - a.score);

  const definitions = event.signals.map((id) => SIGNAL_CATALOG[id]);
  return {
    eventId: event.id,
    overall: aggregateScore(definitions),
    confidence: aggregateConfidence(definitions),
    categories,
    modelVersion: "local-rules-1",
    rulesetVersion: POLICY_VERSION,
  };
}

export function decide(risk: RiskAssessment, eventId: string): PrecogDecision {
  const score = risk.overall;
  const recommendedAction: PolicyAction = score < 30 ? "allow" : score < 60 ? "warn" : score < 80 ? "challenge" : "block";
  const allowedActions: PolicyAction[] = recommendedAction === "allow"
    ? ["allow"]
    : recommendedAction === "warn"
      ? ["warn", "allow"]
      : recommendedAction === "challenge"
        ? ["challenge", "block"]
        : ["block"];
  return {
    id: randomId(),
    eventId,
    risk,
    allowedActions,
    recommendedAction,
    requiresUserInteraction: recommendedAction !== "allow",
    policyVersion: POLICY_VERSION,
    explanationKeys: [`policy.range.${recommendedAction}`],
    externalEscalationAllowed: false,
  };
}

export function initialState(): PersistedState {
  return {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    consent: { enabled: false, updatedAt: null },
    entries: [],
  };
}

function entryCore(entry: Omit<AuditEntry, "entryHash"> | AuditEntry): Omit<AuditEntry, "entryHash"> {
  const { entryHash: _entryHash, ...core } = entry as AuditEntry;
  return core;
}

async function verifyState(raw: string | null | undefined): Promise<PersistedState> {
  if (raw === null || raw === undefined) return initialState();
  if (typeof raw !== "string" || raw.length > 2_000_000) {
    throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat mérete vagy típusa érvénytelen.");
  }

  let state: PersistedState;
  try {
    state = JSON.parse(raw) as PersistedState;
  } catch {
    throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat nem olvasható JSON.");
  }
  if (!state || state.schemaVersion !== AUDIT_SCHEMA_VERSION || !Array.isArray(state.entries)
      || !state.consent || typeof state.consent.enabled !== "boolean"
      || !(state.consent.updatedAt === null || typeof state.consent.updatedAt === "string")
      || state.entries.length > MAX_AUDIT_ENTRIES) {
    throw new PrecogError("AUDIT_INVALID", "A helyi audit-adat sémája hibás vagy túllépte a kapacitást.");
  }

  let previousHash = ZERO_HASH;
  for (let index = 0; index < state.entries.length; index += 1) {
    const entry = state.entries[index];
    if (!entry || entry.seq !== index + 1 || entry.previousHash !== previousHash
        || typeof entry.entryHash !== "string" || !/^[a-f0-9]{64}$/.test(entry.entryHash)
        || !Number.isFinite(entry.risk) || entry.risk < 0 || entry.risk > 100
        || !Number.isFinite(entry.confidence) || entry.confidence < 0 || entry.confidence > 1
        || typeof entry.eventDigest !== "string" || typeof entry.decisionDigest !== "string") {
      throw new PrecogError("AUDIT_INTEGRITY", `A hash-lánc szerkezete hibás a ${index + 1}. bejegyzésnél.`);
    }
    const expectedHash = await sha256(entryCore(entry));
    if (expectedHash !== entry.entryHash) {
      throw new PrecogError("AUDIT_INTEGRITY", `A hash-lánc módosítást jelez a ${index + 1}. bejegyzésnél.`);
    }
    previousHash = entry.entryHash;
  }

  // A local opt-out is fail-safe. Opt-in must have a matching, integrity-chained consent receipt.
  if (state.consent.enabled) {
    const last = state.entries.at(-1);
    if (!last || !last.consentEnabled || last.consentUpdatedAt !== state.consent.updatedAt) {
      throw new PrecogError("CONSENT_INTEGRITY", "Az aktív hozzájáruláshoz nem található érvényes auditnyugta.");
    }
  }
  return state;
}

export async function loadAuditSnapshot(store: AuditStore): Promise<AuditSnapshot> {
  const state = await verifyState(await store.read());
  return {
    state,
    integrity: "ok",
    headHash: state.entries.at(-1)?.entryHash ?? ZERO_HASH,
  };
}

export interface AssessAndAppendResult {
  event: PrecogEvent;
  risk: RiskAssessment;
  decision: PrecogDecision;
  entry: AuditEntry;
  state: PersistedState;
}

export async function assessAndAppend(
  store: AuditStore,
  input: unknown,
  consentOverride?: { enabled: boolean; updatedAt: string | null },
): Promise<AssessAndAppendResult> {
  const event = sanitizeEvent(input);
  const snapshot = await loadAuditSnapshot(store);
  if (snapshot.state.entries.length >= MAX_AUDIT_ENTRIES) {
    throw new PrecogError("AUDIT_CAPACITY_REACHED", "A helyi napló elérte az 1000 bejegyzéses MVP-korlátot.");
  }

  const risk = assessRisk(event);
  const decision = decide(risk, event.id);
  const previousHash = snapshot.headHash;
  const consent = consentOverride ?? snapshot.state.consent;
  const core: Omit<AuditEntry, "entryHash"> = {
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
    previousHash,
  };
  const entry: AuditEntry = { ...core, entryHash: await sha256(core) };
  const state: PersistedState = {
    schemaVersion: AUDIT_SCHEMA_VERSION,
    consent,
    entries: [...snapshot.state.entries, entry],
  };
  await store.write(stableStringify(state));
  return { event, risk, decision, entry, state };
}

export interface ConsentUpdateResult {
  state: PersistedState;
  auditRecorded: boolean;
}

export async function updateConsent(store: AuditStore, enabled: boolean): Promise<ConsentUpdateResult> {
  const snapshot = await loadAuditSnapshot(store);
  const updatedAt = new Date().toISOString();
  try {
    const result = await assessAndAppend(
      store,
      {
        source: "custom",
        type: enabled ? "precog.consent.enabled" : "precog.consent.disabled",
        signals: [],
      },
      { enabled, updatedAt },
    );
    return { state: result.state, auditRecorded: true };
  } catch (error) {
    const precogError = error instanceof PrecogError ? error : null;
    if (!enabled && precogError?.code === "AUDIT_CAPACITY_REACHED") {
      // Stopping collection must remain possible even when the append-only ledger is full.
      const state: PersistedState = {
        ...snapshot.state,
        consent: { enabled: false, updatedAt },
      };
      await store.write(stableStringify(state));
      return { state, auditRecorded: false };
    }
    throw error;
  }
}
