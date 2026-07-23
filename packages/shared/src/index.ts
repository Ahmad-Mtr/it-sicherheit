import semver from "semver";

/**
 * Matches an installed version against an affected-range string.
 * Supports semver ranges/comparators (">=1.0.0 <2.0.0", "<4.17.21") as well
 * as plain exact-version strings. Non-semver-coercible inputs fall back to
 * exact string equality.
 */
export function matchesVersionRange(installedVersion: string, range: string): boolean {
  const coercedInstalled = semver.valid(semver.coerce(installedVersion));
  if (!coercedInstalled) return installedVersion === range;

  if (semver.validRange(range)) {
    try {
      return semver.satisfies(coercedInstalled, range, { includePrerelease: true });
    } catch {
      return false;
    }
  }
  return installedVersion === range;
}

export interface AffectedSoftwareEntry {
  product: string;
  versions: string[];
}

export type Role = "user" | "admin";

export interface JwtPayload {
  sub: string;
  email: string;
  role: Role;
}
