/// <reference types="@penpot/plugin-types" />
import {
  assessAndAppend,
  loadAuditSnapshot,
  updateConsent,
  type AuditStore,
  type EventSource,
} from "./precog-core.ts";

const STORAGE_KEY = "genesis.precog.local-mvp.v1";
function getRoot() {
  const root = penpot.root;
  if (!root) throw new Error("Nincs megnyitott Penpot-tervfájl a helyi audit tárolásához.");
  return root;
}

const store: AuditStore = {
  read: () => getRoot().getPluginData(STORAGE_KEY) ?? null,
  write: (value) => getRoot().setPluginData(STORAGE_KEY, value),
};

const TEST_SCENARIOS: Record<string, { label: string; signals: string[] }> = {
  "phishing-high": {
    label: "Adathalászat – magas kockázat",
    signals: ["phishing.domain_known_bad", "phishing.credential_harvest", "phishing.url_homoglyph"],
  },
  "malware-file": {
    label: "Gyanús fájl – MIME-eltérés",
    signals: ["malware.mime_mismatch"],
  },
  "privacy-export": {
    label: "Érzékeny adat kiexportálása",
    signals: ["privacy.sensitive_export"],
  },
};

penpot.ui.open("DömösAiTech – helyi védelem", "plugin.html", {
  width: 420,
  height: 650,
});

function send(type: string, payload: unknown = {}) {
  penpot.ui.sendMessage({ type, payload });
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "Ismeretlen hiba történt.";
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
      entries: snapshot.state.entries.slice(-12).reverse(),
    });
  } catch (error) {
    send("security-state", {
      enabled: false,
      integrity: "error",
      count: 0,
      entries: [],
      error: describeError(error),
    });
  }
}

async function guardPluginOperation(type: string): Promise<{ allowed: boolean; monitored: boolean }> {
  const snapshot = await loadAuditSnapshot(store);
  if (!snapshot.state.consent.enabled) return { allowed: true, monitored: false };

  const result = await assessAndAppend(store, {
    source: "custom" satisfies EventSource,
    type,
    signals: [],
  });
  await sendState();
  return {
    allowed: result.decision.recommendedAction !== "block",
    monitored: true,
  };
}

async function handle(message: { type?: unknown; payload?: unknown }) {
  const type = typeof message?.type === "string" ? message.type : "";
  const payload = message?.payload && typeof message.payload === "object"
    ? message.payload as Record<string, unknown>
    : {};

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
          auditRecorded: result.auditRecorded,
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
          send("error", { message: "Előbb engedélyezd a helyi védelmet ehhez a Penpot-fájlhoz." });
          return;
        }
        const result = await assessAndAppend(store, {
          source: "custom",
          type: "precog.demo.incident",
          signals: scenario.signals,
          demo: true,
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
          seq: result.entry.seq,
        });
        await sendState();
        return;
      }

      case "get-selection": {
        const gate = await guardPluginOperation("penpot.selection.read");
        if (!gate.allowed) {
          send("error", { message: "A helyi policy letiltotta a műveletet." });
          return;
        }
        const selection = penpot.selection.map((shape) => ({ id: shape.id, name: shape.name }));
        send("selection", { selection, monitored: gate.monitored });
        return;
      }

      case "create-rect": {
        const gate = await guardPluginOperation("penpot.shape.create_rectangle");
        if (!gate.allowed) {
          send("error", { message: "A helyi policy letiltotta a műveletet." });
          return;
        }
        const rect = penpot.createRectangle();
        rect.name = "Új téglalap";
        rect.x = 100;
        rect.y = 100;
        rect.resize(200, 150);
        rect.fills = [{ fillColor: "#4361ee" }];
        send("operation-result", {
          message: gate.monitored
            ? "Téglalap létrehozva; a helyi policy engedélyezte és naplózta a műveletet."
            : "Téglalap létrehozva; a helyi védelem jelenleg ki van kapcsolva.",
        });
        return;
      }

      case "hello":
        send("operation-result", { message: "Helló, DömösAiTech!" });
        return;

      default:
        send("error", { message: "Ismeretlen pluginüzenet." });
    }
  } catch (error) {
    // If a consented, in-scope action cannot be audited, do not perform that action.
    send("error", { message: `A művelet biztonsági ellenőrzése nem sikerült: ${describeError(error)}` });
    await sendState();
  }
}

penpot.ui.onMessage<{ type: string; payload?: unknown }>((message) => {
  void handle(message);
});
