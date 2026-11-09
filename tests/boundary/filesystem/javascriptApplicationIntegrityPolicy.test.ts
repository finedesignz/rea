import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { createPackageWithOptions } from "@electron/asar";
import { expect, it } from "vitest";

import { analyzeJavaScriptApplication } from "../../../src/application/javascript/JavaScriptApplicationService.js";
import { reconstructJavaScriptArtifact } from "../../../src/application/javascript/JavaScriptArtifactReconstruction.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

/** Pack an app whose unpacked native addon is altered after packing (sign-after-pack). */
const createSignedAfterPackAsar = async (): Promise<string> => {
  const root = await createTestTempDirectory("rea-js-integrity-policy-");
  const source = join(root, "source");
  await mkdir(join(source, "native"), { recursive: true });
  await writeFile(join(source, "package.json"), '{"main":"main.js"}\n');
  await writeFile(join(source, "main.js"), "console.log('ok');\n");
  await writeFile(join(source, "native", "addon.node"), "unsigned-addon");
  const archive = join(root, "app.asar");
  await createPackageWithOptions(source, archive, { unpack: "*.node" });
  await writeFile(
    join(`${archive}.unpacked`, "native", "addon.node"),
    "unsigned-addon-with-authenticode-signature",
  );
  return archive;
};

it("fails by default when an unpacked ASAR entry no longer matches its header", async () => {
  const archive = await createSignedAfterPackAsar();

  const result = await analyzeJavaScriptApplication({
    input_path: archive,
    format: "asar",
  });

  expect(result.ok).toBe(false);
  if (result.ok) return;
  const projected = projectAnalysisError(result.error);
  expect(projected.code).toBe("artifact_integrity_mismatch");
  expect(JSON.stringify(projected)).toContain("native/addon.node");
});

it("records the mismatch as an untrusted limitation and continues with record-and-continue", async () => {
  const archive = await createSignedAfterPackAsar();

  const result = await reconstructJavaScriptArtifact({
    input_path: archive,
    format: "asar",
    integrity_policy: "record-and-continue",
  });

  expect(result.graph.nodes.length).toBeGreaterThan(0);
  expect(result.graph.coverage.status).not.toBe("complete");
  const recorded = result.graph.limitations.filter((limitation) =>
    limitation.startsWith(
      "Integrity contradiction recorded for native/addon.node:",
    ),
  );
  expect(recorded).toHaveLength(1);
  expect(recorded[0]).toContain("untrusted");

  const evidence = await analyzeJavaScriptApplication({
    input_path: archive,
    format: "asar",
    integrity_policy: "record-and-continue",
  });
  expect(evidence.ok).toBe(true);
});

const sha256 = (text: string): string =>
  createHash("sha256").update(text).digest("hex");

it("exposes structured integrity_contradictions and records the policy in Evidence", async () => {
  const archive = await createSignedAfterPackAsar();

  const evidence = await analyzeJavaScriptApplication({
    input_path: archive,
    format: "asar",
    integrity_policy: "record-and-continue",
  });

  expect(evidence.ok).toBe(true);
  if (!evidence.ok) return;
  expect(evidence.value.parameters).toMatchObject({
    integrity_policy: "record-and-continue",
  });
  const result = evidence.value.normalized_result as unknown as {
    readonly integrity_contradictions: readonly Record<string, unknown>[];
  };
  expect(result.integrity_contradictions).toHaveLength(1);
  expect(result.integrity_contradictions[0]).toMatchObject({
    logical_path: "native/addon.node",
    declared_sha256: sha256("unsigned-addon"),
    observed_sha256: sha256("unsigned-addon-with-authenticode-signature"),
    trust: "observed-untrusted",
  });
});

it("records the fail policy and an empty contradiction list for a default clean run", async () => {
  const root = await createTestTempDirectory("rea-js-integrity-clean-");
  await mkdir(join(root, "app"), { recursive: true });
  await writeFile(join(root, "app", "package.json"), '{"main":"main.js"}\n');
  await writeFile(join(root, "app", "main.js"), "console.log('ok');\n");

  const evidence = await analyzeJavaScriptApplication({
    input_path: join(root, "app"),
    format: "directory",
  });

  expect(evidence.ok).toBe(true);
  if (!evidence.ok) return;
  expect(evidence.value.parameters).toMatchObject({ integrity_policy: "fail" });
  expect(
    (
      evidence.value.normalized_result as unknown as {
        integrity_contradictions: unknown[];
      }
    ).integrity_contradictions,
  ).toEqual([]);
});
