import type { DynamicToolCallResponse } from "../codex/app-server/protocol.js";
import type { StartSessionOptions } from "../base-agent.js";

/** Main-process capability. Not part of any JSON/IPC request or saved task options. */
export const RESTRICTED_PARTNER = Symbol("cindy.restricted-partner");
export type RestrictedPartnerEffect = "start" | "model" | "resource" | "result";
export interface RestrictedPartnerIdentity {
  readonly version: 1;
  readonly partnerId: string;
  readonly principalId: string;
  readonly grantId: string;
  readonly grantRevision: number;
  readonly inputId: string;
  readonly runId: string;
}
export interface RestrictedPartnerTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
  invoke(
    args: unknown,
    call: { callId: string; runId: string },
  ): Promise<DynamicToolCallResponse>;
}
export interface RestrictedPartnerInput {
  readonly identity: Readonly<RestrictedPartnerIdentity>;
  /** Only the explicitly projected partner persona/subject memory, never owner task context. */
  readonly instructions: string;
  readonly readPaths: readonly string[];
  readonly tools: readonly RestrictedPartnerTool[];
  assertCurrent(effect: RestrictedPartnerEffect): void;
}
const minted = new WeakSet<object>();
function freezeSchema<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freezeSchema(child);
    Object.freeze(value);
  }
  return value;
}
const token = (x: unknown): x is string =>
  typeof x === "string" && /^[a-zA-Z0-9_.:-]{1,200}$/.test(x);
export function mintRestrictedPartnerInput(
  identity: RestrictedPartnerIdentity,
  projection: {
    instructions: string;
    readPaths: string[];
    tools?: RestrictedPartnerTool[];
  },
  assertCurrent: (effect: RestrictedPartnerEffect) => void,
): RestrictedPartnerInput {
  if (
    identity.version !== 1 ||
    !["partnerId", "principalId", "grantId", "inputId", "runId"].every((k) =>
      token(identity[k as keyof RestrictedPartnerIdentity]),
    ) ||
    !Number.isSafeInteger(identity.grantRevision) ||
    identity.grantRevision < 1 ||
    typeof projection.instructions !== "string" ||
    projection.instructions.length > 64_000 ||
    !Array.isArray(projection.readPaths) ||
    projection.readPaths.length > 64 ||
    projection.readPaths.some(
      (p) => typeof p !== "string" || !p || p.includes("\0"),
    ) ||
    typeof assertCurrent !== "function"
  )
    throw new Error("RESTRICTED_PARTNER_INVALID");
  const tools = projection.tools ?? [];
  if (
    !Array.isArray(tools) ||
    tools.length > 16 ||
    new Set(tools.map((t) => t.name)).size !== tools.length ||
    tools.some(
      (t) =>
        !/^partner_[a-z0-9_]{1,60}$/.test(t.name) ||
        [
          "partner_read_file",
          "partner_list_directory",
          "partner_view_image",
        ].includes(t.name) ||
        typeof t.description !== "string" ||
        t.description.length > 4000 ||
        typeof t.invoke !== "function" ||
        !t.inputSchema ||
        t.inputSchema.type !== "object" ||
        JSON.stringify(t.inputSchema).length > 16000,
    )
  )
    throw new Error("RESTRICTED_PARTNER_TOOL_INVALID");
  const checked = (effect: RestrictedPartnerEffect): void => {
    const outcome = assertCurrent(effect) as unknown;
    if (outcome && typeof (outcome as { then?: unknown }).then === "function") {
      void Promise.resolve(outcome).catch(() => undefined);
      throw new Error("RESTRICTED_PARTNER_ASYNC_AUTHORITY");
    }
  };
  const value = Object.freeze({
    identity: Object.freeze({ ...identity }),
    instructions: projection.instructions,
    readPaths: Object.freeze([...projection.readPaths]),
    tools: Object.freeze(
      tools.map((t) =>
        Object.freeze({
          ...t,
          inputSchema: freezeSchema(structuredClone(t.inputSchema)),
        }),
      ),
    ),
    assertCurrent: checked,
  });
  minted.add(value);
  value.assertCurrent("start");
  return value;
}
/** Invoked before runner startup/private-context loading, not after model submission. */
export function restrictedPartnerInput(
  opts: StartSessionOptions,
  runner: string,
): RestrictedPartnerInput | undefined {
  const value = opts[RESTRICTED_PARTNER];
  if (value === undefined) return;
  if (!value || !minted.has(value))
    throw new Error("RESTRICTED_PARTNER_INVALID");
  if (
    runner !== "codex" ||
    process.platform !== "darwin" ||
    opts.remoteHostId ||
    opts.deviceHosted ||
    opts.resumeSessionId ||
    ("agentDeviceId" in opts && opts.agentDeviceId) ||
    opts.reviewMode ||
    opts.permissionMode === "bypassPermissions"
  )
    throw new Error("RESTRICTED_PARTNER_RUNNER_UNSUPPORTED");
  value.assertCurrent("start");
  return value;
}

/** Native allowlist, not a prompt. Per-resource reads go through guarded flat tools. */
export const RESTRICTED_CODEX_CONFIG: Readonly<Record<string, unknown>> =
  Object.freeze({
    project_doc_max_bytes: 0,
    "features.shell_tool": false,
    "features.unified_exec": false,
    "features.shell_snapshot": false,
    "features.view_image": false,
    "features.code_mode": false,
    "features.code_mode_only": false,
    "features.js_repl": false,
    "features.browser_use": false,
    "features.browser_use_external": false,
    "features.computer_use": false,
    "features.image_generation": false,
    "features.multi_agent": false,
    "features.multi_agent_v2": false,
    "features.remote_plugin": false,
    "features.apps": false,
    "features.hooks": false,
    "memories.generate_memories": false,
    "memories.use_memories": false,
    web_search: "disabled",
  });
