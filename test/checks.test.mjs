import test from "node:test";
import assert from "node:assert/strict";
import { evaluateObservation } from "../src/checks.mjs";

const now = new Date("2026-10-03T00:00:00Z");
const healthy = () => ({
  url: "https://example.com", hostname: "example.com", observedAt: now.toISOString(),
  http: { status: 200, headers: { "content-type": "text/html; charset=utf-8", "strict-transport-security": "max-age=31536000; includeSubDomains", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; frame-ancestors 'none'" } },
  tls: { authorized: true, validTo: "2027-01-01T00:00:00Z" },
  dns: { spf: { status: "ok", records: ["v=spf1 -all"] }, dmarc: { status: "ok", records: ["v=DMARC1; p=reject"] }, mx: { status: "ok", records: [] } },
});
const evaluate = (edit) => { const value = healthy(); edit?.(value); return evaluateObservation(value, now); };
const ids = (findings) => findings.map((finding) => finding.ruleId);
const onlyDns = (name, records, status = "ok") => evaluateObservation({ url: "https://example.com", dns: { [name]: { status, records } } }, now);

test("healthy evidence produces no review findings; partial observations do not invent checks", () => {
  assert.deepEqual(evaluate(), []);
  assert.deepEqual(evaluateObservation({ url: "https://example.com" }, now), []);
});

test("HSTS accepts quoted ages and extensions; rejects disabled and malformed policies", () => {
  for (const value of ['max-age="31536000"', 'max-age="\\1\\0"', 'MAX-AGE=10; extension="x;y"', "max-age=99999999999999999999"]) {
    assert.deepEqual(evaluate((o) => { o.http.headers["strict-transport-security"] = value; }), []);
  }
  assert.ok(ids(evaluate((o) => { delete o.http.headers["strict-transport-security"]; })).includes("SPECTYN_HSTS_MISSING"));
  assert.ok(ids(evaluate((o) => { o.http.headers["strict-transport-security"] = "max-age=0"; })).includes("SPECTYN_HSTS_DISABLED"));
  for (const value of ["max-age=-1", "max-age=abc", "max-age=10; max-age=20", "max-age=10, max-age=20", "includeSubDomains", "max-age=10; includeSubDomains=true"]) {
    assert.ok(ids(evaluate((o) => { o.http.headers["strict-transport-security"] = value; })).includes("SPECTYN_HSTS_INVALID"), value);
  }
  assert.ok(!ids(evaluate((o) => { o.url = "http://example.com"; delete o.http.headers["strict-transport-security"]; })).some((id) => id.includes("HSTS")));
});

test("HTML-only CSP and framing checks preserve response context", () => {
  for (const type of ["application/json", "image/png", "text/html, application/json", "", "text/html-incorrect"]) {
    const result = evaluate((o) => { o.http.headers["content-type"] = type; delete o.http.headers["content-security-policy"]; });
    assert.ok(!ids(result).some((id) => /CSP|FRAMING/.test(id)), type);
  }
  const result = evaluate((o) => { delete o.http.headers["content-security-policy"]; o.http.headers["content-security-policy-report-only"] = "frame-ancestors 'none'"; });
  assert.ok(ids(result).includes("SPECTYN_CSP_MISSING"));
  assert.ok(ids(result).includes("SPECTYN_FRAMING_POLICY_MISSING"));
  assert.match(result.find((f) => f.ruleId === "SPECTYN_CSP_MISSING").evidence, /report-only/);
});

test("missing or ambiguous Content-Type leaves document policy unassessed", () => {
  for (const type of [undefined, "", ["text/html", "application/json"], ["text/html", "text/html"], "text/html, application/json"]) {
    const result = evaluate((o) => { o.http.headers["content-type"] = type; delete o.http.headers["content-security-policy"]; });
    assert.deepEqual(ids(result), ["SPECTYN_CONTENT_TYPE_UNASSESSED"]);
    assert.equal(result[0].severity, "info");
    assert.equal(result[0].state, "Not assessable");
  }
  assert.deepEqual(evaluate((o) => { o.http.headers["content-type"] = ["text/html"]; }), []);
});

test("XFO and CSP framing checks account for alternative policies and directive precedence", () => {
  for (const xfo of ["DENY", "sameorigin"]) {
    assert.ok(!ids(evaluate((o) => { o.http.headers["content-security-policy"] = "default-src 'self'"; o.http.headers["x-frame-options"] = xfo; })).some((id) => id.includes("FRAMING")));
  }
  const broad = evaluate((o) => { o.http.headers["content-security-policy"] = "frame-ancestors *"; o.http.headers["x-frame-options"] = "DENY"; });
  assert.ok(ids(broad).includes("SPECTYN_FRAMING_POLICY_BROAD"));
  assert.ok(!ids(evaluate((o) => { o.http.headers["content-security-policy"] = "frame-ancestors *, frame-ancestors 'none'"; })).some((id) => id.includes("FRAMING")));
  assert.ok(ids(evaluate((o) => { o.http.headers["content-security-policy"] = "frame-ancestors *; frame-ancestors 'none'"; })).includes("SPECTYN_FRAMING_POLICY_BROAD"));
  for (const policy of ["frame-ancestors", "frame-ancestors; default-src 'self'", "frame-ancestors *, frame-ancestors"]) {
    assert.deepEqual(evaluate((o) => { o.http.headers["content-security-policy"] = policy; }), []);
  }
});

test("duplicate singleton response headers cannot look healthy; separate CSP policies intersect", () => {
  for (const [name, value, ruleId] of [
    ["strict-transport-security", ["max-age=10", "max-age=10"], "SPECTYN_HSTS_INVALID"],
    ["x-content-type-options", ["nosniff", "nosniff"], "SPECTYN_NOSNIFF_MISSING_OR_INVALID"],
    ["x-frame-options", ["DENY", "DENY"], "SPECTYN_FRAMING_POLICY_MISSING"],
  ]) {
    const result = evaluate((o) => { o.http.headers[name] = value; if (name === "x-frame-options") o.http.headers["content-security-policy"] = "default-src 'self'"; });
    assert.deepEqual(ids(result), [ruleId]);
  }
  for (const csp of [["frame-ancestors *", "frame-ancestors 'none'"], ["frame-ancestors *", "frame-ancestors"]]) {
    assert.deepEqual(evaluate((o) => { o.http.headers["content-security-policy"] = csp; }), []);
  }
});

test("redirects and error pages provide context without implying application document findings", () => {
  for (const status of [301, 302, 307, 404, 500]) {
    const result = evaluate((o) => { o.http.status = status; o.http.headers = { "content-type": "text/html", "strict-transport-security": "max-age=10" }; });
    assert.equal(result.length, 1);
    assert.equal(result[0].severity, "info");
    assert.equal(result[0].ruleId, status < 400 ? "SPECTYN_HTTP_REDIRECT" : "SPECTYN_HTTP_ERROR_RESPONSE");
  }
  for (const status of [204, 205]) assert.deepEqual(evaluate((o) => { o.http.status = status; o.http.headers = { "strict-transport-security": "max-age=10" }; }), []);
});

test("nosniff is checked on successful non-HTML responses without asserting CSP applicability", () => {
  const result = evaluate((o) => { o.http.headers["content-type"] = "application/json"; o.http.headers["x-content-type-options"] = "nosniff, nosniff"; });
  assert.deepEqual(ids(result), ["SPECTYN_NOSNIFF_MISSING_OR_INVALID"]);
});

test("certificate expiry boundaries use exact elapsed time", () => {
  for (const [days, severity] of [[31, null], [30, "medium"], [8, "medium"], [7, "high"], [0, "high"], [-1, "high"]]) {
    const result = evaluate((o) => { o.tls.validTo = new Date(now.getTime() + days * 86400000).toISOString(); });
    assert.equal(result.length, severity ? 1 : 0);
    if (severity) assert.equal(result[0].severity, severity);
  }
  for (const value of [null, "bad timestamp"]) {
    const result = evaluate((o) => { o.tls.validTo = value; });
    assert.deepEqual(ids(result), ["SPECTYN_TLS_EXPIRY_UNKNOWN"]);
    assert.equal(result[0].state, "Not assessable");
  }
});

test("DNS errors remain unknown and do not expose resolver error text", () => {
  const result = evaluate((o) => { for (const name of ["spf", "dmarc", "mx"]) o.dns[name] = { status: "error", records: [], error: "SECRET_RESOLVER\u001b[31m" }; });
  assert.deepEqual(ids(result), ["SPECTYN_DNS_CHECK_INCOMPLETE"]);
  assert.equal(result[0].state, "Not assessable");
  assert.doesNotMatch(JSON.stringify(result), /SECRET|\u001b/);
  const absent = evaluate((o) => { o.dns.spf = o.dns.dmarc = { status: "absent", records: [] }; });
  assert.deepEqual(ids(absent), ["SPECTYN_SPF_NOT_OBSERVED", "SPECTYN_DMARC_NOT_OBSERVED"]);
  assert.match(absent[1].evidence, /parent-domain policy may apply/);
  assert.equal(absent[1].severity, "info");
});

test("SPF policy checks preserve record boundaries and mechanism order", () => {
  assert.equal(onlyDns("spf", ["v=spf1 -all", "v=spf1 ~all"])[0].ruleId, "SPECTYN_SPF_MULTIPLE");
  for (const policy of ["v=spf1 all", "v=spf1 +all", "v=spf1 include:example.org +all"]) {
    assert.equal(onlyDns("spf", [policy])[0].severity, "high");
  }
  assert.deepEqual(onlyDns("spf", ["v=spf1 -all +all"]), []);
  assert.deepEqual(onlyDns("spf", ["v=spf1 redirect=example.org"]), []);
  assert.equal(onlyDns("spf", ["v=spf1 ~all"])[0].ruleId, "SPECTYN_SPF_SOFT_POLICY");
  assert.equal(onlyDns("spf", ["v=spf1 ?all"])[0].ruleId, "SPECTYN_SPF_SOFT_POLICY");
  assert.equal(onlyDns("spf", ["v=spf1 mx"])[0].ruleId, "SPECTYN_SPF_IMPLICIT_NEUTRAL");
  for (const policy of ["v=spf1 redirect=a.example redirect=b.example", "v=spf1 all:anything", "v=spf1\n-all"]) assert.equal(onlyDns("spf", [policy])[0].ruleId, "SPECTYN_SPF_INVALID");
  assert.deepEqual(onlyDns("spf", ["unrelated-verification=record", "v=spf1 -all"]), []);
});

test("DMARC checks distinguish record ambiguity, invalid tags and monitoring", () => {
  assert.equal(onlyDns("dmarc", ["v=DMARC1; p=reject", "v=DMARC1; p=none"])[0].ruleId, "SPECTYN_DMARC_MULTIPLE");
  for (const policy of ["v=DMARC1; p=nonsense", "v=dmarc1; p=reject", "v=DMARC1; p=reject; p=none", "v=DMARC1; sp=bad", "v=DMARC1; t=maybe"]) {
    assert.equal(onlyDns("dmarc", [policy])[0].ruleId, "SPECTYN_DMARC_INVALID", policy);
  }
  for (const policy of ["v=DMARC1", "v=DMARC1; p=none"]) assert.equal(onlyDns("dmarc", [policy])[0].ruleId, "SPECTYN_DMARC_MONITORING");
  assert.deepEqual(onlyDns("dmarc", ["v=DMARC1; p=quarantine"]), []);
  assert.deepEqual(onlyDns("dmarc", ["v=DMARC1;\tp=reject"]), []);
});

test("DMARC 2026 test mode is understood without interpreting obsolete pct as enforcement", () => {
  assert.equal(onlyDns("dmarc", ["v=DMARC1; p=reject; t=y"])[0].ruleId, "SPECTYN_DMARC_TEST_MODE");
  assert.deepEqual(onlyDns("dmarc", ["v=DMARC1; p=reject; pct=0"]), []);
  assert.deepEqual(onlyDns("dmarc", ["v=DMARC1; p=reject; t=n; np=reject"]), []);
});

test("findings exclude cookies, raw policies, DNS payloads and URL credentials", () => {
  const result = evaluate((o) => {
    o.url = "https://user:SECRET_PASSWORD@example.com/intended-path?token=SECRET_QUERY#SECRET_FRAGMENT";
    o.http.headers = { "content-type": "text/html", "set-cookie": "SECRET_COOKIE", authorization: "SECRET_HEADER", "strict-transport-security": "SECRET_HSTS", "x-frame-options": "SECRET_XFO" };
    o.dns.spf = { status: "ok", records: ["v=spf1 include:SECRET_DOMAIN +all"] };
    o.dns.dmarc = { status: "ok", records: ["v=DMARC1; p=none; rua=mailto:SECRET_MAILBOX@example.com"] };
  });
  assert.ok(result.length > 0);
  assert.doesNotMatch(JSON.stringify(result), /SECRET_/);
  assert.ok(result.every((finding) => finding.target === "https://example.com/intended-path"));
});

test("findings retain the exact endpoint pathname within an origin", () => {
  for (const path of ["/", "/account", "/admin/status"]) {
    const result = evaluate((o) => { o.url = `https://example.com${path}`; delete o.http.headers["strict-transport-security"]; });
    assert.equal(result[0].target, `https://example.com${path}`);
  }
});

test("rule evaluation is offline and does not mutate input", () => {
  const observation = healthy(), before = structuredClone(observation), originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("Unexpected network request"); };
  try { assert.deepEqual(evaluateObservation(observation, now), []); assert.deepEqual(observation, before); }
  finally { globalThis.fetch = originalFetch; }
});
