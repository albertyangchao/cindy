import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import type { Logger } from "../../interfaces/logger.js";
import { CodexAgent } from "./index.js";
import {
  RESTRICTED_PARTNER,
  mintRestrictedPartnerInput,
} from "../shared/restricted-partner.js";

// Explicit opt-in; never load the user's Codex home or credentials.
const binaryPath = process.env.CINDY_CODEX_TEST_BINARY;
const legacyBinaryPath = process.env.CINDY_CODEX_LEGACY_TEST_BINARY;
const logger: Logger = {
  trace() {},
  debug() {},
  info() {},
  warn() {},
  error() {},
  fatal() {},
  child: () => logger,
};

// Production CodexAgent + real pinned native app-server; only the provider is loopback fake.
// Existing Review tests do not cover partner persona/native-deny configuration. Native tier.
describe.skipIf(!binaryPath || process.platform !== "darwin")(
  "restricted partner native contract",
  () => {
    it("runs an existing partner with native tools and owner context excluded", async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "cindy-review-project-doc-"),
      );
      const home = path.join(root, "codex");
      const workingDir = path.join(root, "repo", "work");
      const projectRule = "ANCESTOR_PROJECT_RULE_MUST_NOT_REACH_REVIEW";
      const workspaceRule = "WORKSPACE_PROJECT_RULE_MUST_REACH_REVIEW";
      const reviewEvidence = "CINDY_STRUCTURED_REVIEW_EVIDENCE";
      const persona = "APPROVED_EXISTING_PARTNER_PERSONA";
      const calls = [
        ["partner_approved_tool", {}],
        ["partner_read_file", { path: "evidence.txt" }],
        ["partner_read_file", { path: "../private.txt" }],
        ["partner_read_file", { path: "not-granted.txt" }],
        ["shell_command", { command: "echo unsafe > mutated.txt" }],
        [
          "apply_patch",
          {
            patch:
              "*** Begin Patch\n*** Add File: mutated.txt\n+unsafe\n*** End Patch",
          },
        ],
      ] as const;
      const requests: unknown[] = [];
      const server = createServer(async (req, res) => {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const request = JSON.parse(Buffer.concat(chunks).toString());
        requests.push(request);
        const step = requests.length - 1;
        const call = calls[step];
        const reviewResult = JSON.stringify(request).includes(reviewEvidence)
          ? "P2 fixture finding: structured review evidence reached the model"
          : "fixture failure: structured review evidence missing";
        res.writeHead(200, {
          "content-type": "text/event-stream",
          connection: "close",
        });
        const events = [
          { type: "response.created", response: { id: "response-fixture" } },
          {
            type: "response.output_item.done",
            item: call
              ? {
                  type: "function_call",
                  id: `item-${step}`,
                  call_id: `call-${step}`,
                  name: call[0],
                  arguments: JSON.stringify(call[1]),
                }
              : {
                  type: "message",
                  role: "assistant",
                  id: "message-fixture",
                  content: [{ type: "output_text", text: reviewResult }],
                },
          },
          {
            type: "response.completed",
            response: {
              id: "response-fixture",
              usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
            },
          },
        ];
        res.end(
          events
            .map(
              (event) =>
                `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`,
            )
            .join(""),
        );
      });
      let agent: CodexAgent | undefined;
      try {
        await mkdir(home);
        await mkdir(path.join(root, "repo", ".git"), { recursive: true });
        await mkdir(workingDir, { recursive: true });
        await writeFile(path.join(root, "repo", "AGENTS.md"), projectRule);
        await writeFile(path.join(workingDir, "AGENTS.md"), workspaceRule);
        await writeFile(
          path.join(workingDir, "evidence.txt"),
          "APPROVED_RESOURCE",
        );
        await writeFile(
          path.join(workingDir, "not-granted.txt"),
          "PRIVATE_UNGRANTED_WORKSPACE_DATA",
        );
        await writeFile(
          path.join(home, "AGENTS.md"),
          "PRIVATE_HOME_INSTRUCTIONS",
        );
        await writeFile(
          path.join(root, "repo", "private.txt"),
          "PRIVATE_OWNER_DATA",
        );
        await new Promise<void>((resolve) =>
          server.listen(0, "127.0.0.1", resolve),
        );
        const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        await writeFile(
          path.join(home, "config.toml"),
          [
            'model="fixture-model"',
            'model_provider="fixture"',
            'cli_auth_credentials_store="ephemeral"',
            "check_for_update_on_startup=false",
            "[analytics]",
            "enabled=false",
            "[model_providers.fixture]",
            'name="Fixture"',
            `base_url="${endpoint}"`,
            'wire_api="responses"',
            "requires_openai_auth=false",
            "request_max_retries=0",
          ].join("\n"),
        );
        agent = new CodexAgent({
          binaryPath: binaryPath!,
          logger,
          runtimeConfig: { systemPrompt: "PRIVATE_OWNER_SYSTEM_PROMPT" },
          resolveCodexLocalAuthPolicy: () => "isolated",
          prepareCodexExtraSpawnConfig: async () => ({
            extraArgs: [
              "-c",
              'model_provider="fixture"',
              "-c",
              'model_providers.fixture.name="Fixture"',
              "-c",
              `model_providers.fixture.base_url="${endpoint}"`,
              "-c",
              'model_providers.fixture.wire_api="responses"',
              "-c",
              "model_providers.fixture.requires_openai_auth=false",
              "-c",
              "model_providers.fixture.stream_max_retries=0",
              "-c",
              "model_providers.fixture.request_max_retries=0",
            ],
            extraEnv: {},
            codexProxyActive: true,
            restrictedEgressGuarded: true,
          }),
          auth: {
            getState: async () => ({ authenticated: true }),
            triggerLogin: async () => ({ authenticated: true }),
            logout: async () => {},
            getAuthEnv: async () => ({
              HOME: root,
              USERPROFILE: root,
              APPDATA: root,
              LOCALAPPDATA: root,
              CODEX_HOME: home,
              TMPDIR: root,
              OPENAI_API_KEY: "",
              CODEX_API_KEY: "",
              HTTP_PROXY: "http://127.0.0.1:1",
              HTTPS_PROXY: "http://127.0.0.1:1",
              ALL_PROXY: "http://127.0.0.1:1",
              NO_PROXY: "127.0.0.1,localhost",
            }),
          },
        });
        const handle = await agent.startSession({
          sessionId: "review-project-doc",
          providerId: "cprov-fixture",
          model: "fixture-model",
          workingDir,
          [RESTRICTED_PARTNER]: mintRestrictedPartnerInput(
            {
              version: 1,
              partnerId: "bot_existing",
              principalId: "subject",
              grantId: "grant",
              grantRevision: 1,
              inputId: "input",
              runId: "run",
            },
            {
              instructions: persona,
              readPaths: [path.join(workingDir, "evidence.txt")],
              tools: [
                {
                  name: "partner_approved_tool",
                  description: "Approved scoped tool",
                  inputSchema: {
                    type: "object",
                    properties: {},
                    additionalProperties: false,
                  },
                  invoke: async () => ({
                    success: true,
                    contentItems: [
                      { type: "inputText", text: "APPROVED_TOOL_RESULT" },
                    ],
                  }),
                },
              ],
            },
            () => {},
          ),
          makerMemoryEnabled: false,
        });
        const receivedEvents: unknown[] = [];
        const events = (async () => {
          for await (const event of handle.events()) {
            receivedEvents.push(event);
            if (event.type === "error") throw new Error(JSON.stringify(event));
            if (event.type === "done") return;
          }
        })();
        await handle.send(
          { type: "user", content: `Review the fixture: ${reviewEvidence}` },
          { throwOnStartFailure: true },
        );
        await events;
        expect(requests).toHaveLength(calls.length + 1);
        const requestPayload = JSON.stringify(requests);
        expect(requestPayload).toContain(reviewEvidence);
        expect(requestPayload).not.toContain(workspaceRule);
        expect(requestPayload).toContain(persona);
        expect(requestPayload).toContain("APPROVED_RESOURCE");
        expect(requestPayload).toContain("APPROVED_TOOL_RESULT");
        expect(requestPayload).not.toContain("PRIVATE_OWNER_DATA");
        expect(requestPayload).not.toContain("PRIVATE_OWNER_SYSTEM_PROMPT");
        expect(requestPayload).not.toContain(
          "PRIVATE_UNGRANTED_WORKSPACE_DATA",
        );
        expect(requestPayload).not.toContain("PRIVATE_HOME_INSTRUCTIONS");
        await expect(
          readFile(path.join(workingDir, "mutated.txt")),
        ).rejects.toMatchObject({ code: "ENOENT" });
        await expect(
          handle.send(
            { type: "user", content: "duplicate" },
            { throwOnStartFailure: true },
          ),
        ).rejects.toThrow("NO_RESUBMIT");
        expect(requestPayload).not.toContain(projectRule);
        expect(JSON.stringify(receivedEvents)).toContain(
          "P2 fixture finding: structured review evidence reached the model",
        );
        await handle.close();
      } finally {
        try {
          await agent?.dispose();
        } finally {
          try {
            if (server.listening) {
              await new Promise<void>((resolve) =>
                server.close(() => resolve()),
              );
            }
          } finally {
            await rm(root, {
              recursive: true,
              force: true,
              maxRetries: 5,
              retryDelay: 100,
            });
          }
        }
      }
    }, 30_000);
  },
);

describe.skipIf(!binaryPath || process.platform !== "darwin")(
  "restricted native uncertain provider",
  () => {
    it("does not resubmit a failed native model request or accept a duplicate input", async () => {
      const root = await mkdtemp(
        path.join(tmpdir(), "cindy-restricted-no-retry-"),
      );
      const home = path.join(root, "home"),
        work = path.join(root, "work");
      let calls = 0;
      await mkdir(home);
      await mkdir(work);
      const server = createServer((req, res) => {
        calls++;
        req.resume();
        res
          .writeHead(503, { "content-type": "application/json" })
          .end('{"error":{"message":"synthetic upstream failure"}}');
      });
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      const agent = new CodexAgent({
        binaryPath: binaryPath!,
        logger,
        runtimeConfig: {},
        resolveCodexLocalAuthPolicy: () => "isolated",
        prepareCodexExtraSpawnConfig: async () => ({
          codexProxyActive: true,
          restrictedEgressGuarded: true,
          extraEnv: {},
          extraArgs: [
            "-c",
            'model_provider="fixture"',
            "-c",
            'model_providers.fixture.name="Fixture"',
            "-c",
            `model_providers.fixture.base_url="${endpoint}"`,
            "-c",
            'model_providers.fixture.wire_api="responses"',
            "-c",
            "model_providers.fixture.requires_openai_auth=false",
            "-c",
            "model_providers.fixture.request_max_retries=0",
            "-c",
            "model_providers.fixture.stream_max_retries=0",
            "-c",
            "model_providers.fixture.supports_websockets=false",
          ],
        }),
        auth: {
          getState: async () => ({ authenticated: true }),
          triggerLogin: async () => ({ authenticated: true }),
          logout: async () => {},
          getAuthEnv: async () => ({
            HOME: root,
            USERPROFILE: root,
            APPDATA: root,
            LOCALAPPDATA: root,
            CODEX_HOME: home,
            TMPDIR: root,
            OPENAI_API_KEY: "",
            CODEX_API_KEY: "",
            HTTP_PROXY: "http://127.0.0.1:1",
            HTTPS_PROXY: "http://127.0.0.1:1",
            ALL_PROXY: "http://127.0.0.1:1",
            NO_PROXY: "127.0.0.1,localhost",
          }),
        },
      });
      try {
        const handle = await agent.startSession({
          sessionId: "uncertain-run",
          model: "fixture-model",
          providerId: "cprov-fixture",
          workingDir: work,
          [RESTRICTED_PARTNER]: mintRestrictedPartnerInput(
            {
              version: 1,
              partnerId: "bot_existing",
              principalId: "subject",
              grantId: "grant",
              grantRevision: 1,
              inputId: "input",
              runId: "uncertain-run",
            },
            { instructions: "Approved persona", readPaths: [] },
            () => {},
          ),
        });
        const terminal = (async () => {
          for await (const e of handle.events())
            if (e.type === "error" || e.type === "done") return;
          throw Error("MISSING_TERMINAL");
        })();
        void terminal.catch(() => {});
        try {
          await handle.send(
            { type: "user", content: "Synthetic question" },
            { throwOnStartFailure: true },
          );
        } catch {}
        await terminal;
        expect(calls).toBe(1);
        await expect(
          handle.send(
            { type: "user", content: "duplicate" },
            { throwOnStartFailure: true },
          ),
        ).rejects.toThrow("NO_RESUBMIT");
        expect(calls).toBe(1);
        await handle.close();
      } finally {
        await agent.dispose();
        await new Promise<void>((r) => server.close(() => r()));
        await rm(root, { recursive: true, force: true });
      }
    }, 30000);
  },
);
