#!/usr/bin/env node
/**
 * Copies the pentest case catalog (JSON) next to the compiled package output.
 *
 * tsc compiles TS but does not copy JSON assets, and the catalog loader reads
 * `../cases/*.json` relative to its own module (tests/lib in dev, tests/dist/lib
 * here). Run after `tsc` so consumers of the built package (the server app via
 * @sentinel/pentest, or node directly) can load the catalog.
 */

import { cpSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(here, "..", "cases");
const target = path.join(here, "..", "dist", "cases");

if (existsSync(source)) {
  cpSync(source, target, { recursive: true });
  console.log("copied pentest cases -> " + path.relative(process.cwd(), target));
} else {
  console.warn("no pentest cases at " + source);
}
