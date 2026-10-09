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
