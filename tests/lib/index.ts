/**
 * @sentinel/evaluation — public entry point.
 *
 * The pentest library: tagged bypass catalog, per-middleware profiles, harness,
 * perf and summary. Provider-agnostic: the middleware surface under test is
 * injected via `EvaluationDeps` (see profiles.ts). The server app and the CLI both
 * build their own deps and call the same library.
 */

export * from "./types.js";
export * from "./tags.js";
export * from "./catalog.js";
export * from "./profiles.js";
export * from "./harness.js";
export * from "./perf.js";
export * from "./summary.js";
