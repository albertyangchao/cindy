import { describe, expect, it } from "vitest";
import {
  RESTRICTED_PARTNER,
  RESTRICTED_CODEX_CONFIG,
  mintRestrictedPartnerInput,
  restrictedPartnerInput,
} from "./restricted-partner.js";
import type { StartSessionOptions } from "../base-agent.js";
// Production boundary: all runner start methods call restrictedPartnerInput before private context.
// Covers a new opt-in security contract; existing Review tests don't cover per-input partner permits.
// Minimal input is a Host-minted identity and a synchronous revision guard. Unit tier, no IO/model.
const identity = {
  version: 1 as const,
  partnerId: "bot_existing",
  principalId: "subject",
  grantId: "grant",
  grantRevision: 1,
  inputId: "input",
  runId: "run",
};
const options = { sessionId: "run", model: "fixture", workingDir: "/fixture" };
const mint = (guard = () => {}) =>
  mintRestrictedPartnerInput(
    identity,
    { instructions: "Approved persona", readPaths: [] },
    guard,
  );
describe("restricted native partner boundary", () => {
  it("preserves ordinary runner behavior", () => {
    for (const kind of ["codex", "claude-code", "pi"])
      expect(restrictedPartnerInput(options, kind)).toBeUndefined();
  });
  it("requires a minted Host capability, not a serialized prompt or receipt", () => {
    expect(() =>
      restrictedPartnerInput(
        {
          ...options,
          [RESTRICTED_PARTNER]: JSON.parse(JSON.stringify(mint())),
        },
        "codex",
      ),
    ).toThrow("INVALID");
  });
  it.each(["pi", "claude-code", "remote"])(
    "rejects unsupported runner %s before dispatch",
    (kind) => {
      expect(() =>
        restrictedPartnerInput(
          { ...options, [RESTRICTED_PARTNER]: mint() },
          kind,
        ),
      ).toThrow("UNSUPPORTED");
    },
  );
  it.each([
    { resumeSessionId: "owner-history" },
    { remoteHostId: "remote" },
    { deviceHosted: {} },
    { agentDeviceId: "device" },
    { reviewMode: true },
    { permissionMode: "bypassPermissions" },
  ])("rejects context widening %j", (extra) => {
    expect(() =>
      restrictedPartnerInput(
        {
          ...options,
          ...extra,
          [RESTRICTED_PARTNER]: mint(),
        } as StartSessionOptions,
        "codex",
      ),
    ).toThrow("UNSUPPORTED");
  });
  it("freezes identity and projected paths", () => {
    const input = mint();
    expect(Object.isFrozen(input.identity)).toBe(true);
    expect(Object.isFrozen(input.readPaths)).toBe(true);
    expect(
      restrictedPartnerInput(
        { ...options, [RESTRICTED_PARTNER]: input },
        "codex",
      ),
    ).toBe(input);
  });
  it("checks revocation on start", () => {
    let current = true;
    const input = mint(() => {
      if (!current) throw Error("REVOKED");
    });
    current = false;
    expect(() =>
      restrictedPartnerInput(
        { ...options, [RESTRICTED_PARTNER]: input },
        "codex",
      ),
    ).toThrow("REVOKED");
  });
  it("native configuration disables independent egress, tools and native delegation", () => {
    expect(RESTRICTED_CODEX_CONFIG).toMatchObject({
      project_doc_max_bytes: 0,
      web_search: "disabled",
      "features.shell_tool": false,
      "features.unified_exec": false,
      "features.view_image": false,
      "features.multi_agent": false,
      "memories.use_memories": false,
    });
  });
});
