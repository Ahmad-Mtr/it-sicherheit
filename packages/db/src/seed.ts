import { db } from "./client";
import { cwe, cve, cveCweMap, user } from "./schema";
import type { AffectedSoftwareEntry } from "@vuln/shared";

// ---------------------------------------------------------------------------
// CWEs — 29 real, commonly-seen weakness categories (NVD/MITRE naming).
// ---------------------------------------------------------------------------
const CWES = [
  { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)", description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page served to other users.", potentialImpact: "Execution of attacker-controlled script in a victim's browser session, session hijacking, defacement." },
  { id: "CWE-89", name: "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", description: "The software constructs all or part of an SQL command using externally-influenced input without neutralizing special elements.", potentialImpact: "Unauthorized read/write of database contents, authentication bypass, in some cases remote code execution." },
  { id: "CWE-78", name: "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)", description: "The software constructs all or part of an OS command using externally-influenced input without neutralizing special elements that could modify the command.", potentialImpact: "Arbitrary command execution on the host operating system." },
  { id: "CWE-77", name: "Improper Neutralization of Special Elements used in a Command (Command Injection)", description: "The software constructs a command using externally-influenced input but does not neutralize special elements that could be interpreted as control syntax.", potentialImpact: "Execution of unintended commands with the privileges of the vulnerable application." },
  { id: "CWE-22", name: "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", description: "The software uses external input to construct a pathname intended to identify a file or directory beneath a restricted parent directory, but does not neutralize sequences such as '..' that resolve to a location outside that directory.", potentialImpact: "Disclosure or modification of arbitrary files outside the intended directory." },
  { id: "CWE-352", name: "Cross-Site Request Forgery (CSRF)", description: "The web application does not, or cannot, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.", potentialImpact: "State-changing actions performed on behalf of an authenticated user without their consent." },
  { id: "CWE-434", name: "Unrestricted Upload of File with Dangerous Type", description: "The software allows an attacker to upload or transfer files of a dangerous type that can be automatically processed within the product's environment.", potentialImpact: "Remote code execution via uploaded web shells or malicious scripts." },
  { id: "CWE-502", name: "Deserialization of Untrusted Data", description: "The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.", potentialImpact: "Remote code execution, denial of service, or object injection depending on the deserialization gadget chain available." },
  { id: "CWE-611", name: "Improper Restriction of XML External Entity Reference (XXE)", description: "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside the intended sphere of control.", potentialImpact: "Disclosure of local files, server-side request forgery, denial of service." },
  { id: "CWE-798", name: "Use of Hard-coded Credentials", description: "The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication or outbound communication.", potentialImpact: "Full compromise of the affected component by any party aware of the hard-coded value." },
  { id: "CWE-306", name: "Missing Authentication for Critical Function", description: "The software does not perform any authentication for functionality that requires a provable user identity or consumes significant computational resources.", potentialImpact: "Unauthenticated access to sensitive functionality or data." },
  { id: "CWE-862", name: "Missing Authorization", description: "The software does not perform an authorization check when an actor attempts to access a resource or perform an action.", potentialImpact: "Access to resources or actions that should be restricted to a subset of users." },
  { id: "CWE-863", name: "Incorrect Authorization", description: "The software performs an authorization check, but the check is incorrect, allowing access that should have been denied.", potentialImpact: "Privilege escalation or access to another user's data due to a flawed authorization decision." },
  { id: "CWE-287", name: "Improper Authentication", description: "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.", potentialImpact: "Impersonation of legitimate users, unauthorized account access." },
  { id: "CWE-269", name: "Improper Privilege Management", description: "The software does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control.", potentialImpact: "Escalation of privileges beyond what was intended for the actor." },
  { id: "CWE-200", name: "Exposure of Sensitive Information to an Unauthorized Actor", description: "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.", potentialImpact: "Disclosure of internal data, credentials, or system details useful for further attacks." },
  { id: "CWE-522", name: "Insufficiently Protected Credentials", description: "The software transmits or stores authentication credentials using an insecure method susceptible to unauthorized interception or retrieval.", potentialImpact: "Credential theft leading to account takeover." },
  { id: "CWE-327", name: "Use of a Broken or Risky Cryptographic Algorithm", description: "The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.", potentialImpact: "Decryption or forgery of protected data by an attacker with moderate resources." },
  { id: "CWE-330", name: "Use of Insufficiently Random Values", description: "The software uses insufficiently random numbers or values in a security context that depends on unpredictability.", potentialImpact: "Prediction of tokens, session identifiers, or cryptographic material." },
  { id: "CWE-119", name: "Improper Restriction of Operations within the Bounds of a Memory Buffer", description: "The software performs operations on a memory buffer, but it can read from or write to a memory location outside of the intended boundary of the buffer.", potentialImpact: "Memory corruption leading to crashes or arbitrary code execution." },
  { id: "CWE-120", name: "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)", description: "The program copies an input buffer to an output buffer without verifying that the size of the input buffer is less than or equal to the size of the output buffer.", potentialImpact: "Stack or heap corruption, potentially leading to arbitrary code execution." },
  { id: "CWE-125", name: "Out-of-bounds Read", description: "The software reads data past the end, or before the beginning, of the intended buffer.", potentialImpact: "Disclosure of adjacent memory contents or a crash." },
  { id: "CWE-787", name: "Out-of-bounds Write", description: "The software writes data past the end, or before the beginning, of the intended buffer.", potentialImpact: "Memory corruption that can lead to crashes or arbitrary code execution." },
  { id: "CWE-416", name: "Use After Free", description: "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.", potentialImpact: "Arbitrary code execution or information disclosure via reuse of freed memory." },
  { id: "CWE-476", name: "NULL Pointer Dereference", description: "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL.", potentialImpact: "Denial of service via application crash." },
  { id: "CWE-190", name: "Integer Overflow or Wraparound", description: "The software performs a calculation that can produce an integer overflow or wraparound, when the logic assumes the resulting value will be larger than the original value.", potentialImpact: "Buffer overflows, incorrect resource allocation, or logic errors exploitable for further attack." },
  { id: "CWE-918", name: "Server-Side Request Forgery (SSRF)", description: "The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but does not sufficiently ensure that the request is being sent to the expected destination.", potentialImpact: "Access to internal network resources or cloud metadata endpoints not reachable externally." },
  { id: "CWE-732", name: "Incorrect Permission Assignment for Critical Resource", description: "The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.", potentialImpact: "Unauthorized read or write access to sensitive files or configuration." },
  { id: "CWE-1021", name: "Improper Restriction of Rendered UI Layers or Frames (Clickjacking)", description: "The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain, allowing a malicious layer to be rendered on top.", potentialImpact: "Tricking users into performing unintended actions via an invisible overlaid UI." },
] as const;

// ---------------------------------------------------------------------------
// Product pool — the set of products the seeded CVEs reference, so
// `GET /api/cves?product=X&version=Y` searches have realistic matches.
// ---------------------------------------------------------------------------
const PRODUCTS = [
  "lodash", "express", "axios", "jsonwebtoken", "minimist", "node-fetch",
  "moment", "ejs", "socket.io", "jquery", "openssl", "libxml2", "curl",
  "sqlite", "imagemagick", "ffmpeg", "yaml", "handlebars", "marked", "semver",
] as const;

function affected(product: string, versions: string[]): AffectedSoftwareEntry[] {
  return [{ product, versions }];
}

interface CveSeed {
  id: string;
  description: string;
  affectedSoftware: AffectedSoftwareEntry[];
  cvssScore: string;
  publishedDate: string;
  cweIds: string[];
}

// Anchor CVEs — deliberately reference well-known packages/versions so the
// product/version search endpoint has guaranteed hits to demonstrate against.
const ANCHOR_CVES: CveSeed[] = [
  { id: "CVE-2023-10001", description: "Prototype pollution in lodash allows attackers to modify Object.prototype via a crafted payload passed to merge/mergeWith, leading to denial of service or, in some deployments, remote code execution.", affectedSoftware: affected("lodash", ["<4.17.21"]), cvssScore: "9.1", publishedDate: "2023-02-14", cweIds: ["CWE-1021", "CWE-862"] },
  { id: "CVE-2023-10002", description: "express fails to properly encode redirect Location headers built from user input, allowing reflected cross-site scripting on error pages.", affectedSoftware: affected("express", ["<4.18.2"]), cvssScore: "6.1", publishedDate: "2023-04-02", cweIds: ["CWE-79"] },
  { id: "CVE-2023-10003", description: "axios follows redirects across origins while still attaching the original Authorization header, leaking credentials to a third-party host under attacker control.", affectedSoftware: affected("axios", ["<1.6.0"]), cvssScore: "7.5", publishedDate: "2023-08-19", cweIds: ["CWE-522", "CWE-200"] },
  { id: "CVE-2023-10004", description: "jsonwebtoken accepts tokens signed with the 'none' algorithm when the verify options are misconfigured, allowing forged tokens to bypass signature checks.", affectedSoftware: affected("jsonwebtoken", ["<9.0.0"]), cvssScore: "9.8", publishedDate: "2023-01-10", cweIds: ["CWE-287", "CWE-327"] },
  { id: "CVE-2023-10005", description: "minimist is vulnerable to prototype pollution via the '__proto__' key in parsed command-line arguments.", affectedSoftware: affected("minimist", ["<1.2.8"]), cvssScore: "8.1", publishedDate: "2023-03-30", cweIds: ["CWE-1021"] },
  { id: "CVE-2023-10006", description: "node-fetch does not strip sensitive headers when following a cross-origin redirect, exposing cookies and authorization headers to the redirect target.", affectedSoftware: affected("node-fetch", ["<2.6.7"]), cvssScore: "6.5", publishedDate: "2023-05-22", cweIds: ["CWE-200"] },
  { id: "CVE-2022-10007", description: "moment's user-supplied locale string is used to build a RegExp without sanitization, enabling a regular-expression denial of service (ReDoS).", affectedSoftware: affected("moment", ["<2.29.4"]), cvssScore: "5.3", publishedDate: "2022-11-04", cweIds: ["CWE-1021"] },
  { id: "CVE-2022-10008", description: "ejs allows template options passed from user-controlled data to be interpreted as executable template code, resulting in server-side template injection and remote code execution.", affectedSoftware: affected("ejs", ["<3.1.7"]), cvssScore: "9.8", publishedDate: "2022-07-13", cweIds: ["CWE-94", "CWE-77"] },
  { id: "CVE-2022-10009", description: "socket.io's CORS handling reflects an arbitrary Origin header when no explicit allow-list is configured, permitting cross-origin WebSocket connections from untrusted sites.", affectedSoftware: affected("socket.io", ["<4.6.2"]), cvssScore: "7.4", publishedDate: "2022-09-27", cweIds: ["CWE-863"] },
  { id: "CVE-2021-10010", description: "jquery's $.htmlPrefilter mishandles certain crafted HTML fragments, enabling execution of attacker-controlled script when the fragment is injected into the DOM.", affectedSoftware: affected("jquery", ["<3.5.0"]), cvssScore: "6.1", publishedDate: "2021-05-04", cweIds: ["CWE-79"] },

  // Real-world OpenSSL CVEs + "Copy Fail" (recent Linux kernel privesc).
  { id: "CVE-2014-0160", description: "OpenSSL's TLS/DTLS heartbeat extension (RFC 6520) does not bounds-check the payload length field, allowing a remote attacker to read up to 64KB of process memory per request — including private keys and session secrets ('Heartbleed').", affectedSoftware: affected("openssl", [">=1.0.1 <1.0.1g"]), cvssScore: "7.5", publishedDate: "2014-04-07", cweIds: ["CWE-125", "CWE-119"] },
  { id: "CVE-2022-3602", description: "A crafted X.509 certificate with a specially formed email address triggers a 4-byte stack buffer overflow during punycode decoding in OpenSSL 3.0, leading to a crash or potential remote code execution ('SpookySSL').", affectedSoftware: affected("openssl", [">=3.0.0 <3.0.7"]), cvssScore: "7.5", publishedDate: "2022-11-01", cweIds: ["CWE-787", "CWE-120"] },
  { id: "CVE-2016-0800", description: "OpenSSL servers that still permit SSLv2 enable the DROWN cross-protocol attack, letting an attacker decrypt intercepted TLS sessions by exploiting the weak SSLv2 handshake and export-grade ciphers.", affectedSoftware: affected("openssl", ["<1.0.2g"]), cvssScore: "5.9", publishedDate: "2016-03-01", cweIds: ["CWE-327"] },
  { id: "CVE-2026-31431", description: "A logic flaw in the Linux kernel's AF_ALG userspace crypto interface (algif_aead) mishandles memory during in-place AEAD operations ('Copy Fail'), letting a local unprivileged user corrupt kernel memory and escalate privileges to root. Affects kernels from 2017 through April 2026; public PoC and active exploitation confirmed.", affectedSoftware: affected("linux", ["<6.19.12"]), cvssScore: "7.8", publishedDate: "2026-04-22", cweIds: ["CWE-669", "CWE-1288"] },
];

// CWE-94 (Code Injection) is referenced by one anchor CVE above but is not in
// the primary 29-entry list; add it explicitly so the FK is satisfiable.
const EXTRA_CWES = [
  { id: "CWE-94", name: "Improper Control of Generation of Code (Code Injection)", description: "The software constructs all or part of a code segment using externally-influenced input, but does not neutralize special elements that could modify the syntax or behavior of the intended code segment.", potentialImpact: "Execution of arbitrary code within the context of the vulnerable application." },
  { id: "CWE-669", name: "Incorrect Resource Transfer Between Spheres", description: "The product does not properly transfer a resource or behavior to another sphere, or improperly imports a resource from another sphere, in a manner that provides unintended control over that resource.", potentialImpact: "Corruption or exposure of a resource that crosses a trust boundary — e.g. kernel/user memory mishandling leading to privilege escalation." },
  { id: "CWE-1288", name: "Improper Validation of Consistency within Input", description: "The product receives a complex input with multiple elements or fields that must be consistent with each other, but does not validate, or incorrectly validates, that the input is actually consistent.", potentialImpact: "Processing of internally inconsistent input can drive the code into an unexpected state such as memory corruption." },
];

// ---------------------------------------------------------------------------
// Bulk-generated CVEs to reach >=50 total, spread across the remaining
// products and CWE categories with varied CVSS/dates.
// ---------------------------------------------------------------------------
function mulberry32(seed: number) {
  return function () {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(42);
function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(rand() * arr.length)]!;
}
function randomVersionBound(): string {
  const major = 1 + Math.floor(rand() * 8);
  const minor = Math.floor(rand() * 20);
  const patch = Math.floor(rand() * 20);
  return `<${major}.${minor}.${patch}`;
}
function randomDate(): string {
  const year = 2021 + Math.floor(rand() * 4);
  const month = String(1 + Math.floor(rand() * 12)).padStart(2, "0");
  const day = String(1 + Math.floor(rand() * 28)).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
function randomCvss(): string {
  return (2 + rand() * 8).toFixed(1);
}

const DESCRIPTION_TEMPLATES: Record<string, (p: string) => string> = {
  "CWE-79": (p) => `${p} fails to escape user-supplied content before rendering it in the DOM, allowing stored cross-site scripting via a crafted input field.`,
  "CWE-89": (p) => `${p} builds a database query by concatenating unsanitized user input, allowing an attacker to inject arbitrary SQL via a crafted request parameter.`,
  "CWE-78": (p) => `${p} passes unsanitized user input to a shell command, allowing arbitrary OS command execution.`,
  "CWE-77": (p) => `${p} interpolates user-controlled input into a command string without neutralizing shell metacharacters.`,
  "CWE-22": (p) => `${p} does not canonicalize file paths derived from user input, allowing directory traversal outside the intended storage root.`,
  "CWE-352": (p) => `${p} does not verify an anti-CSRF token on state-changing requests, allowing forged requests from an authenticated user's browser.`,
  "CWE-434": (p) => `${p} does not validate the type of uploaded files, allowing an attacker to upload and later execute a malicious script.`,
  "CWE-502": (p) => `${p} deserializes user-supplied data without validation, allowing object injection and potential remote code execution.`,
  "CWE-611": (p) => `${p}'s XML parser resolves external entities by default, allowing local file disclosure via a crafted XML document.`,
  "CWE-798": (p) => `${p} ships with a hard-coded default credential that is not required to be changed on first run.`,
  "CWE-306": (p) => `${p} exposes an internal management endpoint without requiring authentication.`,
  "CWE-862": (p) => `${p} does not check that the requesting user owns the referenced resource, allowing access to other users' data via direct object reference.`,
  "CWE-863": (p) => `${p}'s authorization check relies on a client-supplied role field, allowing privilege escalation by modifying the request.`,
  "CWE-287": (p) => `${p}'s session validation logic can be bypassed by omitting a specific header, allowing authentication bypass.`,
  "CWE-269": (p) => `${p} grants elevated privileges to a background worker process that are not revoked after the privileged task completes.`,
  "CWE-200": (p) => `${p} includes internal stack traces and configuration values in error responses returned to the client.`,
  "CWE-522": (p) => `${p} stores an authentication token in plaintext in a location readable by other local processes.`,
  "CWE-327": (p) => `${p} defaults to a deprecated cipher suite for encrypting data in transit.`,
  "CWE-330": (p) => `${p} seeds its token generator with a predictable value, allowing session tokens to be guessed.`,
  "CWE-119": (p) => `${p} does not bounds-check a length field parsed from network input before copying it into a fixed-size buffer.`,
  "CWE-120": (p) => `${p} copies attacker-controlled input into a fixed-size stack buffer without validating the input length, resulting in a classic stack buffer overflow.`,
  "CWE-125": (p) => `${p} reads past the end of an internal buffer when parsing a malformed input file, disclosing adjacent heap memory.`,
  "CWE-787": (p) => `${p} writes past the end of a heap-allocated buffer when processing a crafted input, corrupting adjacent heap metadata.`,
  "CWE-416": (p) => `${p} frees an internal object while a reference to it is still held elsewhere, leading to a use-after-free on a subsequent operation.`,
  "CWE-476": (p) => `${p} dereferences a pointer that can be NULL when a specific malformed input is supplied, causing a crash.`,
  "CWE-190": (p) => `${p} performs an unchecked size calculation that can overflow, resulting in a smaller-than-expected buffer allocation.`,
  "CWE-918": (p) => `${p} fetches a URL supplied by the client without restricting the target host, allowing requests to internal network services.`,
  "CWE-732": (p) => `${p} creates a configuration file with world-readable permissions, exposing embedded secrets to other local users.`,
  "CWE-1021": (p) => `${p} does not send an X-Frame-Options or frame-ancestors directive, allowing the interface to be embedded in a malicious iframe.`,
  "CWE-94": (p) => `${p} evaluates a template string containing user-controlled data, allowing injection of arbitrary code.`,
};

const CWE_IDS_FOR_TEMPLATES = Object.keys(DESCRIPTION_TEMPLATES);

function generateBulkCves(count: number, startIndex: number): CveSeed[] {
  const out: CveSeed[] = [];
  for (let i = 0; i < count; i++) {
    const product = pick(PRODUCTS);
    const cweId = pick(CWE_IDS_FOR_TEMPLATES);
    const secondaryCwe = rand() > 0.75 ? pick(CWE_IDS_FOR_TEMPLATES) : null;
    const cweIds = secondaryCwe && secondaryCwe !== cweId ? [cweId, secondaryCwe] : [cweId];
    const year = 2021 + Math.floor(rand() * 4);
    const num = 20000 + startIndex + i;
    out.push({
      id: `CVE-${year}-${num}`,
      description: DESCRIPTION_TEMPLATES[cweId]!(product),
      affectedSoftware: affected(product, [randomVersionBound()]),
      cvssScore: randomCvss(),
      publishedDate: randomDate(),
      cweIds,
    });
  }
  return out;
}

const BULK_CVES = generateBulkCves(45, 1);
const ALL_CVES = [...ANCHOR_CVES, ...BULK_CVES];

async function main() {
  console.log(`Seeding ${CWES.length + EXTRA_CWES.length} CWEs, ${ALL_CVES.length} CVEs...`);

  await db.insert(cwe).values([...CWES, ...EXTRA_CWES]).onConflictDoNothing();

  await db.insert(cve).values(
    ALL_CVES.map((c) => ({
      id: c.id,
      description: c.description,
      affectedSoftware: c.affectedSoftware,
      cvssScore: c.cvssScore,
      publishedDate: c.publishedDate,
    })),
  ).onConflictDoNothing();

  const mappings = ALL_CVES.flatMap((c) =>
    c.cweIds.map((cweId) => ({ cveId: c.id, cweId })),
  );
  await db.insert(cveCweMap).values(mappings).onConflictDoNothing();

  const adminPasswordHash = await Bun.password.hash("Admin123!");
  const userPasswordHash = await Bun.password.hash("User123!");
  await db.insert(user).values([
    { id: "admin-seed-1", email: "admin@example.com", passwordHash: adminPasswordHash, role: "admin" },
    { id: "user-seed-1", email: "user@example.com", passwordHash: userPasswordHash, role: "user" },
  ]).onConflictDoNothing();

  console.log("Seed complete.");
  console.log("Login: admin@example.com / Admin123! (admin), user@example.com / User123! (user)");
}

await main();
process.exit(0);
