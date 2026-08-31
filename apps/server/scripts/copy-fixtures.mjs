#!/usr/bin/env node
/**
 * Copies the replay fixtures next to the compiled server output.
 *
 * `tsc` compiles TypeScript and copies nothing else, and ReplayRunner resolves
 * its fixtures relative to its own module — `src/fixtures/replay` under tsx,
 * `dist/fixtures/replay` in a built server. Without this step a built server
 * with RUNTIME_PROVIDER=replay loads zero fixtures, reports the runtime as
 * unavailable, and cannot replay anything. It was invisible for as long as it
 * was, because the only thing that exercised replay ran the server from `src`
 * through tsx.
 */

import { cpSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(here, "..", "src", "fixtures");
const target = path.join(here, "..", "dist", "fixtures");

if (!existsSync(source)) {
  console.error("no fixtures at " + source);
  process.exit(1);
}

cpSync(source, target, { recursive: true });
console.log("copied replay fixtures -> " + path.relative(process.cwd(), target));
