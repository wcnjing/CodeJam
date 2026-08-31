import { createHash } from "node:crypto";

/** An authenticated caller. The id is what lands in the audit record. */
export interface Principal {
  id: string;
}

export interface PrincipalRegistryOptions {
  /** Minimum token length. A remote production server raises this to 24. */
  minTokenLength?: number;
}

const ID_PATTERN = /^[A-Za-z0-9._@-]{1,64}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/;

function digestOf(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Maps bearer tokens to named principals.
 *
 * Tokens are retained only as SHA-256 digests, so resolution is a map lookup on
 * the digest rather than a comparison loop: there is no secret-dependent
 * comparison, and the work does not grow with the number of principals
 * configured. Nothing here reads a token back out, which is also why token
 * length is validated during parsing rather than by the caller afterwards.
 */
export class PrincipalRegistry {
  private constructor(private readonly byTokenDigest: Map<string, Principal>) {}

  static parse(raw: string, options: PrincipalRegistryOptions = {}): PrincipalRegistry {
    const minTokenLength = options.minTokenLength ?? 8;
    const byTokenDigest = new Map<string, Principal>();
    const seenIds = new Set<string>();
    const entries = raw
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

    entries.forEach((entry, index) => {
      const position = "entry " + (index + 1) + " of APP_PRINCIPALS";
      const separator = entry.indexOf(":");
      if (separator < 0) {
        // Deliberately does not echo `entry`: a missing id usually means someone
        // pasted a bare token, and the message would leak it.
        throw new Error(position + ' must look like "id:token".');
      }
      const id = entry.slice(0, separator).trim();
      const token = entry.slice(separator + 1).trim();
      if (!ID_PATTERN.test(id)) {
        throw new Error(
          position + " has an invalid id; use 1-64 characters of [A-Za-z0-9._@-].",
        );
      }
      if (token.length === 0) {
        // Same paste-mistake shape as a missing colon ("tok_secret:"), so the id
        // half is very likely the secret. Report it positionally rather than
        // naming it, which would echo the token.
        throw new Error(position + ' must look like "id:token"; the token half is empty.');
      }
      // Everything below reports positionally rather than naming the id. The
      // pair is symmetric, so a swapped "token:id" paste parses as id=<secret>
      // and reaches exactly these branches; naming the id would print the
      // secret into a startup crash log and into cloud-init output. The entry
      // number is just as actionable for an operator reading APP_PRINCIPALS.
      if (!TOKEN_PATTERN.test(token)) {
        throw new Error(
          position + " has an invalid token; use 1-128 URL-safe characters ([A-Za-z0-9._~-]).",
        );
      }
      if (token.length < minTokenLength) {
        throw new Error(
          position + " has a token shorter than the minimum; use at least " +
            minTokenLength +
            " characters.",
        );
      }
      if (token.startsWith("replace-")) {
        throw new Error(position + " still has the placeholder token value.");
      }
      if (seenIds.has(id)) {
        throw new Error(
          position + " has a duplicate id; each principal needs its own name.",
        );
      }
      const tokenDigest = digestOf(token);
      if (byTokenDigest.has(tokenDigest)) {
        throw new Error(
          "APP_PRINCIPALS reuses one token across ids, which makes identity ambiguous.",
        );
      }
      seenIds.add(id);
      byTokenDigest.set(tokenDigest, { id });
    });

    return new PrincipalRegistry(byTokenDigest);
  }

  /** How many principals are configured. Zero means authentication is off. */
  get size(): number {
    return this.byTokenDigest.size;
  }

  resolve(token: string): Principal | null {
    if (!token) return null;
    const principal = this.byTokenDigest.get(digestOf(token));
    return principal ? { ...principal } : null;
  }
}
