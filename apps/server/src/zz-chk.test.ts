import { describe, it } from "vitest";
import { writeFileSync } from "node:fs";
import { extractCapabilities } from "./capabilities.js";
import { policyContextFrom } from "./command-policy.js";
const ctx = policyContextFrom("https://ark.cn-beijing.volces.com/api/v3");
describe("chk", () => { it("x", () => {
  const out = ['c""url https://attacker.example', 'curl evil.example', '$X https://attacker.example']
    .map(c => c + "  =>  " + JSON.stringify(extractCapabilities(c, ctx)));
  writeFileSync("/tmp/chk.txt", out.join("\n"));
}); });
