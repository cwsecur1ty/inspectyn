// Observation-level checks. CSP strength, mail authentication and exploit
// verification are outside this module's scope.
// References: RFC 6797 (HSTS), RFC 7208 (SPF), RFC 9989 (DMARC), MDN headers.
const DAY = 24 * 60 * 60 * 1000;
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

function targetOf(observation) {
  try {
    const url = new URL(observation.url);
    if (["http:", "https:"].includes(url.protocol)) return `${url.origin}${url.pathname}`;
  } catch { /* DNS-only observations can omit the URL. */ }
  return /^[a-z0-9.[\]:-]+$/i.test(observation.hostname ?? "")
    ? observation.hostname : "unknown target";
}

function hstsState(value) {
  // Quoted extension values may contain semicolons.
  const parts = []; let current = "", quoted = false, escaped = false;
  for (const char of value) {
    if (escaped) { current += char; escaped = false; continue; }
    if (quoted && char === "\\") { current += char; escaped = true; continue; }
    if (char === '"') quoted = !quoted;
    if (char === ";" && !quoted) { parts.push(current.trim()); current = ""; }
    else current += char;
  }
  if (quoted || escaped || /[\x00-\x08\x0a-\x1f\x7f]/.test(value)) return "invalid";
  parts.push(current.trim());
  const seen = new Set(); let maxAge;
  for (const part of parts) {
    if (!part) continue;
    const split = part.indexOf("="), name = (split < 0 ? part : part.slice(0, split)).trim().toLowerCase();
    const argument = split < 0 ? undefined : part.slice(split + 1).trim();
    if (!TOKEN.test(name) || seen.has(name)) return "invalid";
    seen.add(name);
    if (argument !== undefined && !TOKEN.test(argument) && !/^"(?:[^"\\\x00-\x1f\x7f]|\\[\x20-\x7e])*"$/.test(argument)) return "invalid";
    if (name === "includesubdomains" && argument !== undefined) return "invalid";
    if (name === "max-age") {
      const seconds = argument?.startsWith('"') ? argument.slice(1, -1).replace(/\\(.)/g, "$1") : argument;
      if (!/^\d+$/.test(seconds ?? "")) return "invalid";
      maxAge = BigInt(seconds);
    }
  }
  return maxAge === undefined ? "invalid" : maxAge === 0n ? "disabled" : "present";
}

function httpChecks(observation, add) {
  if (!observation.http) return;
  const { status, headers = {} } = observation.http;
  const values = (name) => (Array.isArray(headers[name]) ? headers[name] : [headers[name]])
    .filter((value) => typeof value === "string").map((value) => value.trim());
  // CSP field values combine as enforcing policies; singleton headers also
  // require a field-count check.
  const header = (name) => values(name).join(", ");
  if (status >= 300 && status < 400) {
    add("SPECTYN_HTTP_REDIRECT", "info", "Redirect response observed",
      `HTTP ${status} was returned. The redirect destination was not followed or assessed.`,
      "Assess each intended destination explicitly; these findings describe only the original response.");
  } else if (status >= 400 && status < 600) {
    add("SPECTYN_HTTP_ERROR_RESPONSE", "info", "HTTP error response observed",
      `HTTP ${status} was returned. Response-header findings may describe an error or access-control page.`,
      "Confirm the expected public response and review the relevant application route separately.");
  }

  if (String(observation.url).startsWith("https://")) {
    const hsts = header("strict-transport-security"), state = values("strict-transport-security").length > 1 ? "invalid" : hsts ? hstsState(hsts) : "missing";
    if (state !== "present") add(`SPECTYN_HSTS_${state.toUpperCase()}`, "low",
      state === "missing" ? "HSTS response header missing" : state === "disabled" ? "HSTS disabled by max-age=0" : "HSTS policy needs correction",
      state === "missing" ? "No Strict-Transport-Security header was observed on this HTTPS response. Cached or parent-domain policies were not assessed."
        : state === "disabled" ? "The response includes an HSTS max-age of zero."
          : "The response has repeated HSTS header fields or a missing, malformed or duplicated directive.",
      "Review the host's HTTPS policy and configure one valid HSTS policy with a positive max-age. Confirm subdomain readiness before expanding its scope.");
  }

  // CSP and framing checks require a successful response with a clear HTML type.
  // Redirects, empty responses and error pages do not represent the application.
  if (!(status >= 200 && status < 300) || status === 204 || status === 205) return;
  const contentType = header("content-type");
  const unknownContentType = values("content-type").length !== 1 || !contentType || contentType.includes(",")
    || !/^[!#$%&'*+.^_`|~0-9a-z-]+\/[!#$%&'*+.^_`|~0-9a-z-]+(?:\s*;|$)/i.test(contentType);
  if (unknownContentType) add("SPECTYN_CONTENT_TYPE_UNASSESSED", "info", "Document response policy could not be assessed",
    !contentType ? "The successful response has no Content-Type header. HTML-specific CSP and framing checks were not assessed."
      : "The successful response has a repeated or ambiguous Content-Type value. HTML-specific CSP and framing checks were not assessed.",
    "Serve one valid Content-Type for this endpoint, then reassess its document response policies.", "Not assessable");
  const html = !unknownContentType && /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/i.test(contentType);
  const nosniff = header("x-content-type-options");
  if (values("x-content-type-options").length !== 1 || nosniff.toLowerCase() !== "nosniff") add("SPECTYN_NOSNIFF_MISSING_OR_INVALID", "low", "Content-type protection needs review",
    nosniff ? "X-Content-Type-Options is not a single recognized nosniff value." : "No X-Content-Type-Options header was observed on this response.",
    "Set X-Content-Type-Options: nosniff and serve the intended Content-Type on relevant responses.");
  if (!html) return;

  const csp = header("content-security-policy");
  if (!csp) add("SPECTYN_CSP_MISSING", "low", "Enforced CSP response header missing",
    header("content-security-policy-report-only") ? "Only a report-only CSP header was observed on this HTML response. Meta-element policies were not inspected."
      : "No enforced Content-Security-Policy header was observed on this HTML response. Meta-element policies were not inspected.",
    "Develop and test an application-specific CSP, then enforce it after reviewing legitimate resource requirements.");

  const ancestorPolicies = csp.split(",").map((policy) => policy.split(";").map((directive) => directive.trim())
    .find((directive) => /^frame-ancestors(?:\s|$)/i.test(directive)))
    .filter(Boolean).map((directive) => directive.replace(/^frame-ancestors\s*/i, "").trim());
  const xfo = header("x-frame-options");
  if (!ancestorPolicies.length && !(values("x-frame-options").length === 1 && /^(?:DENY|SAMEORIGIN)$/i.test(xfo))) {
    add("SPECTYN_FRAMING_POLICY_MISSING", "low", "Framing response policy needs review",
      "This HTML response has neither an enforced CSP frame-ancestors directive nor a single recognized DENY or SAMEORIGIN X-Frame-Options value.",
      "Review legitimate embedding requirements and set CSP frame-ancestors for the approved parent origins.");
  } else if (ancestorPolicies.length && ancestorPolicies.every((policy) => policy === "*")) {
    add("SPECTYN_FRAMING_POLICY_BROAD", "low", "Framing directive needs review",
      "The observed frame-ancestors directives allow all origins. An enforced CSP directive can take precedence over X-Frame-Options.",
      "Review the intended framing behavior and explicitly restrict ancestors where appropriate.");
  }
}

function spfChecks(result, add) {
  if (!result || result.status === "error") return;
  const records = (result.records ?? []).filter((record) => typeof record === "string" && /^v=spf1(?:\s|$)/i.test(record));
  if (!records.length) {
    add("SPECTYN_SPF_NOT_OBSERVED", "low", "SPF record not observed",
      "No SPF version 1 record was returned for the queried hostname. This does not determine its mail-sending role.",
      "Confirm which domains send mail and publish an appropriate SPF policy after inventorying legitimate senders.");
    return;
  }
  if (records.length > 1) {
    add("SPECTYN_SPF_MULTIPLE", "medium", "Multiple SPF records observed",
      `${records.length} SPF version 1 records were returned at the same hostname. SPF requires a single policy record.`,
      "Consolidate the intended authorization policy into one SPF record and validate it with the mail operator.");
    return;
  }
  const terms = records[0].trim().split(/ +/).slice(1);
  const redirects = terms.filter((term) => /^redirect=/i.test(term));
  if (/[\x00-\x1f\x7f]/.test(records[0]) || redirects.length > 1 || terms.some((term) => /^[+?~-]?all[:/=]/i.test(term))) {
    add("SPECTYN_SPF_INVALID", "medium", "SPF policy syntax needs review",
      "The observed SPF record has a control character, repeated redirect modifier or malformed all mechanism. Other SPF syntax and DNS dependencies were not evaluated.",
      "Validate the full SPF record, including included policies, using an SPF validator and the authoritative mail configuration.");
    return;
  }
  // RFC 7208: all makes later mechanisms and redirect unreachable.
  // Included policies and mechanisms are not evaluated recursively.
  const all = terms.find((term) => /^[+?~-]?all$/i.test(term));
  if (all && /^(?:\+)?all$/i.test(all)) {
    add("SPECTYN_SPF_ALLOW_ALL", "high", "SPF has a permissive all mechanism",
      "The first all mechanism has a pass qualifier. Any sender reaching that mechanism receives an SPF pass; preceding mechanisms were not evaluated.",
      "Review legitimate senders and replace the permissive fallback with the mail owner's intended policy.");
  } else if (all && /^[?~]/.test(all)) {
    add("SPECTYN_SPF_SOFT_POLICY", "low", "SPF fallback requests review",
      all.startsWith("~") ? "The first all mechanism requests softfail. This can be an intentional rollout policy and does not establish a DMARC failure."
        : "The first all mechanism returns neutral. This does not establish how receivers handle mail or whether DMARC passes.",
      "Review the fallback against the authorized sender inventory before deciding whether a fail policy is appropriate.");
  } else if (!all && !redirects.length) {
    add("SPECTYN_SPF_IMPLICIT_NEUTRAL", "low", "SPF has an implicit neutral fallback",
      "No all mechanism or redirect modifier was observed. SPF falls back to neutral when no preceding mechanism matches.",
      "Confirm the intended fallback with the mail operator. The tool does not evaluate mechanisms or DNS lookup limits.");
  }
}

function dmarcChecks(result, add) {
  if (!result || result.status === "error") return;
  const records = (result.records ?? []).filter((record) => typeof record === "string" && /^v\s*=\s*DMARC1(?:\s*;|\s*$)/i.test(record));
  if (!records.length) {
    add("SPECTYN_DMARC_NOT_OBSERVED", "info", "Direct DMARC record not observed",
      "No DMARC record was observed at the queried _dmarc hostname. A parent-domain policy may apply; policy inheritance was not assessed.",
      "Determine the effective DMARC policy for the mail Author Domain, including inherited policy, before changing DNS.");
    return;
  }
  if (records.length > 1) {
    add("SPECTYN_DMARC_MULTIPLE", "medium", "Multiple DMARC records observed",
      `${records.length} DMARC policy records were returned at the same hostname. Policy discovery cannot select a single local policy.`,
      "Consolidate the intended policy into one DMARC record and verify effective policy discovery.");
    return;
  }
  const parts = records[0].split(";").map((part) => part.trim()).filter(Boolean), tags = new Map();
  let invalid = /[\x00-\x08\x0a-\x1f\x7f]/.test(records[0]);
  for (const part of parts) {
    const match = /^([a-z]+)\s*=\s*(.+)$/i.exec(part);
    if (!match) { invalid = true; continue; }
    const name = match[1].toLowerCase();
    if (tags.has(name)) invalid = true;
    tags.set(name, match[2].trim());
  }
  invalid ||= tags.get("v") !== "DMARC1";
  for (const name of ["p", "sp", "np"]) if (tags.has(name) && !/^(?:none|quarantine|reject)$/i.test(tags.get(name))) invalid = true;
  if (tags.has("t") && !/^[yn]$/i.test(tags.get("t"))) invalid = true;
  if (invalid) {
    add("SPECTYN_DMARC_INVALID", "medium", "DMARC policy syntax needs review",
      "The local record has a malformed or repeated tag, invalid version, or unrecognized policy value. Receiver fallback behavior and the full record were not evaluated.",
      "Validate the DMARC record against RFC 9989 and verify effective policy with the mail operator.");
    return;
  }
  if (!tags.has("p") || tags.get("p").toLowerCase() === "none") {
    add("SPECTYN_DMARC_MONITORING", "low", "DMARC monitoring policy observed",
      tags.has("p") ? "The local DMARC record specifies p=none; it does not request quarantine or rejection of failing mail."
        : "The local DMARC record omits p; RFC 9989 describes a default monitoring policy. Effective receiver behavior was not tested.",
      "Review authentication reports and legitimate mail flows before deciding whether an enforcement policy is appropriate.");
  } else if (tags.get("t")?.toLowerCase() === "y") {
    add("SPECTYN_DMARC_TEST_MODE", "low", "DMARC test mode observed",
      "The local DMARC record enables t=y. Under RFC 9989, receivers apply a policy one level below the declared enforcement policy.",
      "Confirm whether test mode is intentional and complete mail-flow review before moving to full enforcement.");
  }
  // RFC 9989 removed pct; historical values do not define enforcement coverage.
}

export function evaluateObservation(observation, now = new Date()) {
  const findings = [], target = targetOf(observation);
  const add = (ruleId, severity, title, evidence, remediation, state) => findings.push({ ruleId, severity, title, evidence, remediation, target, ...(state ? { state } : {}) });
  httpChecks(observation, add);
  if (observation.tls) {
    const expiry = typeof observation.tls.validTo === "string" ? Date.parse(observation.tls.validTo) : NaN;
    if (!Number.isFinite(expiry)) {
      add("SPECTYN_TLS_EXPIRY_UNKNOWN", "info", "Certificate expiry could not be assessed",
        "The TLS observation did not include a valid certificate expiry timestamp.", "Inspect the served certificate and its renewal configuration.", "Not assessable");
    } else {
      const remaining = expiry - new Date(now).getTime();
      if (remaining <= 30 * DAY) add(remaining <= 0 ? "SPECTYN_TLS_EXPIRED" : "SPECTYN_TLS_EXPIRING", remaining <= 7 * DAY ? "high" : "medium",
        remaining <= 0 ? "Certificate expiry has passed" : "Certificate renewal window is approaching",
        `The observed certificate expires at ${new Date(expiry).toISOString()}${remaining > 0 ? ` (within ${Math.ceil(remaining / DAY)} days)` : ""}.`,
        "Verify automated renewal and deployment of the replacement certificate before the expiry deadline.");
    }
  }
  const incomplete = ["spf", "dmarc", "mx"].filter((name) => observation.dns?.[name]?.status === "error");
  if (incomplete.length) add("SPECTYN_DNS_CHECK_INCOMPLETE", "info", "DNS checks incomplete",
    `The following lookups failed: ${incomplete.map((name) => name.toUpperCase()).join(", ")}. Missing-record conclusions were not made for those lookups.`,
    "Retry the failed lookups and check resolver availability before drawing conclusions about DNS policy.", "Not assessable");
  spfChecks(observation.dns?.spf, add);
  dmarcChecks(observation.dns?.dmarc, add);
  return findings;
}
