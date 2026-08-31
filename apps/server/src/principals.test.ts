import { describe, expect, it } from "vitest";
import { PrincipalRegistry } from "./principals.js";

const ALICE = "tok_alice_0123456789abcdef";
const BOB = "tok_bob_0123456789abcdef";

describe("PrincipalRegistry", () => {
  it("resolves a configured token to its principal id", () => {
    const registry = PrincipalRegistry.parse("alice:" + ALICE + ",bob:" + BOB);
    expect(registry.size).toBe(2);
    expect(registry.resolve(ALICE)).toEqual({ id: "alice" });
    expect(registry.resolve(BOB)).toEqual({ id: "bob" });
  });

  it("returns null for an unknown or empty token", () => {
    const registry = PrincipalRegistry.parse("alice:" + ALICE);
    expect(registry.resolve("tok_nope_0123456789abcdef")).toBeNull();
    expect(registry.resolve("")).toBeNull();
  });

  it("treats an empty setting as no principals configured", () => {
    const registry = PrincipalRegistry.parse("");
    expect(registry.size).toBe(0);
    expect(registry.resolve(ALICE)).toBeNull();
  });

  it("tolerates surrounding whitespace between entries", () => {
    const registry = PrincipalRegistry.parse(" alice:" + ALICE + " , bob:" + BOB + " ");
    expect(registry.resolve(ALICE)).toEqual({ id: "alice" });
    expect(registry.resolve(BOB)).toEqual({ id: "bob" });
  });

  it("rejects duplicate ids so two humans cannot share one name", () => {
    expect(() => PrincipalRegistry.parse("alice:" + ALICE + ",alice:" + BOB)).toThrow(
      /duplicate id/i,
    );
  });

  it("rejects one token shared by two ids as ambiguous identity", () => {
    expect(() => PrincipalRegistry.parse("alice:" + ALICE + ",bob:" + ALICE)).toThrow(
      /ambiguous/i,
    );
  });

  it("rejects malformed entries", () => {
    expect(() => PrincipalRegistry.parse("alice")).toThrow(/id:token/i);
    expect(() => PrincipalRegistry.parse(":" + ALICE)).toThrow(/id/i);
    expect(() => PrincipalRegistry.parse("alice:")).toThrow(/token/i);
    expect(() => PrincipalRegistry.parse("alice:has spaces")).toThrow(/URL-safe/i);
    expect(() => PrincipalRegistry.parse("not a valid id:" + ALICE)).toThrow(/id/i);
  });

  it("enforces the caller's minimum token length", () => {
    expect(() => PrincipalRegistry.parse("alice:tok_short", { minTokenLength: 24 })).toThrow(
      /at least 24/i,
    );
    expect(PrincipalRegistry.parse("alice:" + ALICE, { minTokenLength: 24 }).size).toBe(1);
  });

  it("rejects a placeholder token in any environment", () => {
    expect(() => PrincipalRegistry.parse("alice:replace-with-a-real-token")).toThrow(
      /placeholder/i,
    );
  });

  it("never echoes a token in an error message", () => {
    // A bare token with no id is the likeliest paste mistake; the message must
    // point at the entry position, not print the secret back into the logs.
    expect(() => PrincipalRegistry.parse(ALICE)).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining(ALICE) }),
    );
  });

  it("never echoes a bare token pasted with a trailing colon", () => {
    // Same paste mistake, one keystroke further: this parses as id=<the token>,
    // token="", so any message naming the id would print the secret.
    expect(() => PrincipalRegistry.parse(ALICE + ":")).toThrow(
      expect.objectContaining({ message: expect.not.stringContaining(ALICE) }),
    );
  });

  it("never echoes a token pasted in the wrong order", () => {
    // The pair is symmetric, so writing "token:id" parses as id=<the secret>
    // with a token half that then fails a later check. Each entry below trips a
    // different one of those checks; none may name the id back.
    const swapped = [
      ALICE + ":ops", // shorter than the minimum length
      ALICE + ":ops bob", // not URL-safe
      ALICE + ":replace-me", // placeholder prefix
      ALICE + ":ops_one_token," + ALICE + ":ops_two_token", // duplicate id
    ];
    for (const raw of swapped) {
      expect(() => PrincipalRegistry.parse(raw)).toThrow(
        expect.objectContaining({ message: expect.not.stringContaining(ALICE) }),
      );
    }
  });
});
