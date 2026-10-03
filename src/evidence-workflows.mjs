// Derived from the Spectyn evidence workflow engine.
// Original source SHA-256: 599463b187f9c73f7739e5f19d53424f65dd7ab5968d53fb06eacf48a50a7e0b
// Standalone ES module; no build step required.

export const evidenceRecipes = [
    { id: "nuclei-review", title: "Nuclei findings review", category: "Scan results", summary: "Normalise existing HTTP results, group repeat observations and prepare a review queue.", input: "Nuclei HTTP JSON or JSONL", output: "Grouped findings + CVE references" },
    { id: "kev-match", title: "KEV priority review", category: "CVE / KEV", summary: "Match reported CVE IDs against a supplied KEV catalogue, retaining its release date.", input: "Nuclei report + KEV JSON", output: "Exact CVE matches + catalogue context" },
    { id: "cve-applicability", title: "CVE applicability review", category: "CVE / KEV", summary: "Compare inventory with explicit version entries in a supplied CVE record. Keep uncertain matches open.", input: "Product inventory JSON + CVE Record JSON", output: "Exact-version candidates + unresolved evidence" },
    { id: "http-baseline", title: "Spectyn HTTP baseline", category: "Common exposures", summary: "Review supplied response metadata for transport and browser-policy configuration gaps.", input: "HTTP observation JSON", output: "HSTS, CSP and content-type review" },
];
export const EVIDENCE_LIMIT = 2 * 1024 * 1024;
export const CATALOG_LIMIT = 8 * 1024 * 1024;
const maxRecords = 500;
const record = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const string = (v, limit = 180) => typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, limit) : "";
function bounded(text, limit, label) {
    if (!text.trim())
        throw Error(`Add ${label} before running the workflow.`);
    if (new TextEncoder().encode(text).byteLength > limit)
        throw Error(`${label} exceeds the ${limit / 1024 / 1024} MB limit.`);
}
function rows(text) {
    bounded(text, EVIDENCE_LIMIT, "evidence");
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        parsed = text.split(/\r?\n/).flatMap((line, index) => {
            if (!line.trim())
                return [];
            try {
                return [JSON.parse(line)];
            }
            catch {
                throw Error(`Invalid JSON on line ${index + 1}. Use a JSON array, one object or JSONL.`);
            }
        });
    }
    const items = Array.isArray(parsed) ? parsed : [parsed];
    if (items.length > maxRecords)
        throw Error(`Supply up to ${maxRecords} observations per run.`);
    if (items.some(item => !record(item)))
        throw Error("Every observation must be a JSON object.");
    return items;
}
function assetLabel(value) {
    const raw = string(value, 2048);
    try {
        const explicitScheme = raw.includes("://"), url = new URL(explicitScheme ? raw : `https://${raw}`);
        if (!raw || !["http:", "https:"].includes(url.protocol) || !url.hostname)
            throw Error();
        return explicitScheme ? url.origin : url.host;
    }
    catch {
        throw Error("Each observation needs an HTTP(S) URL or hostname. Imported URLs are never requested.");
    }
}
function cveIds(value) {
    const values = Array.isArray(value) ? value : [value];
    return [...new Set(values.map(v => string(v, 30).toUpperCase()).filter(v => /^CVE-\d{4}-\d{4,19}$/.test(v)))].sort();
}
function timestamp(value) { const valueString = string(value, 50); return valueString && /^\d{4}-\d{2}-\d{2}T/.test(valueString) && Number.isFinite(Date.parse(valueString)) ? new Date(valueString).toISOString() : null; }
function catalog(text) {
    bounded(text, CATALOG_LIMIT, "a KEV catalogue");
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        throw Error("The KEV catalogue must be a valid JSON object.");
    }
    if (!record(parsed) || !Array.isArray(parsed.vulnerabilities) || parsed.vulnerabilities.length > 20000)
        throw Error("Use a KEV catalogue with a vulnerabilities array (up to 20,000 entries).");
    const ids = new Set();
    for (const item of parsed.vulnerabilities) {
        if (!record(item) || cveIds(item.cveID).length !== 1)
            throw Error("Each KEV entry must contain a valid cveID.");
        ids.add(cveIds(item.cveID)[0]);
    }
    if (!string(parsed.catalogVersion) || !string(parsed.dateReleased))
        throw Error("The KEV catalogue needs catalogVersion and dateReleased for source context.");
    return { ids, metadata: { version: string(parsed.catalogVersion), releasedAt: string(parsed.dateReleased), origin: "User-supplied KEV catalogue; authenticity not verified" } };
}
const unknownKev = () => ({ state: "Unknown", ids: [] });
function applicability(items, text) {
    bounded(text, EVIDENCE_LIMIT, "a CVE record");
    let parsed;
    try {
        parsed = JSON.parse(text);
    }
    catch {
        throw Error("Supply a valid CVE Record JSON object.");
    }
    if (!record(parsed) || parsed.dataType !== "CVE_RECORD" || typeof parsed.dataVersion !== "string" || !["5.0", "5.1", "5.2"].includes(parsed.dataVersion) || !record(parsed.cveMetadata) || typeof parsed.cveMetadata.cveId !== "string" || !/^CVE-\d{4}-\d{4,19}$/.test(parsed.cveMetadata.cveId) || parsed.cveMetadata.state !== "PUBLISHED" || !record(parsed.containers) || !record(parsed.containers.cna) || !Array.isArray(parsed.containers.cna.affected))
        throw Error("Use a published CVE Record (format 5.0, 5.1 or 5.2) with cveMetadata and containers.cna.affected.");
    const id = cveIds(parsed.cveMetadata.cveId)[0], affected = parsed.containers.cna.affected;
    if (affected.length > 1000)
        throw Error("The supplied CVE record exceeds 1,000 affected-product entries.");
    if (!items.length)
        throw Error("Supply at least one inventory observation.");
    const identity = (v) => typeof v === "string" ? v.trim().toLowerCase() : "";
    const findings = items.map((row, index) => {
        if ([row.vendor, row.product, row.version].some(v => typeof v === "string" && v.length > 180))
            throw Error(`Observation ${index + 1} exceeds the 180-character product or version limit.`);
        const asset = assetLabel(row.asset ?? row.url), vendor = string(row.vendor), product = string(row.product), version = string(row.version), source = string(row.source), observedAt = timestamp(row.observedAt);
        const matches = affected.filter(p => record(p) && vendor && product && identity(p.vendor) === identity(vendor) && identity(p.product) === identity(product));
        let state = "Not assessable", detail = "No exact vendor and product identity matches the supplied CNA data. This does not establish that the asset is unaffected.";
        if (!vendor || !product || !version || /^(unknown|n\/a|unspecified|not specified|none|-)$/i.test(version) || !source || !observedAt)
            detail = "Vendor, product, a known version, inventory source and an ISO observation timestamp are required for an evidence-backed comparison.";
        else if (matches.length) {
            const entries = matches.flatMap(p => Array.isArray(p.versions) ? p.versions : []);
            const exact = entries.filter(v => record(v) && v.version === version && !/[*<>]/.test(version) && v.lessThan === undefined && v.lessThanOrEqual === undefined && v.changes === undefined);
            const statuses = new Set(exact.map(v => v.status));
            // Ranges, platform qualifiers, version transitions and conflicting records need an analyst.
            const qualified = matches.some(p => ["platforms", "modules", "programFiles", "programRoutines"].some(k => p[k] !== undefined && (!Array.isArray(p[k]) || p[k].length > 0)));
            const incomplete = matches.some(p => !Array.isArray(p.versions) || !p.versions.some(v => record(v) && v.version === version));
            const complex = entries.some(v => !record(v) || v.lessThan !== undefined || v.lessThanOrEqual !== undefined || v.changes !== undefined || typeof v.version !== "string" || /[*<>]/.test(v.version));
            if (qualified || complex || incomplete)
                detail = "Matching product found, but incomplete product evidence, ranges, transitions or deployment conditions require manual assessment. No version-range inference was made.";
            else if (statuses.size === 1 && statuses.has("affected")) {
                state = "Needs review";
                detail = "The supplied CNA record explicitly marks this exact version as affected. Confirm inventory accuracy and deployment conditions before remediation.";
            }
            else if (statuses.size === 1 && statuses.has("unaffected")) {
                state = "Not applicable";
                detail = "The supplied CNA record explicitly marks this exact version as unaffected. This applies only to this advisory and supplied inventory observation.";
            }
            else
                detail = "The supplied record has no unambiguous affected or unaffected entry for this exact version. Missing versions and default statuses remain unresolved.";
        }
        return { id: `finding-${index + 1}`, asset, title: `${id} / ${product || "Unspecified product"}`, rule: "spectyn.cve-exact-version.v1", severity: "unknown", state, cves: [id], evidence: `${vendor || "Unknown vendor"} / ${product || "Unknown product"} / ${version || "Unknown version"}. Inventory source: ${source || "Not supplied"}. ${detail}`, recommendation: state === "Needs review" ? "Review the publisher's advisory, deployment conditions and original inventory evidence. This candidate does not confirm exploitability." : "Review the publisher's full version and deployment guidance. An unresolved comparison is not a clean bill of health.", occurrences: 1, observedAt, firstObservedAt: observedAt, kev: unknownKev() };
    });
    return { findings, skipped: 0, grouped: 0, advisory: { id, source: `https://www.cve.org/CVERecord?id=${id}`, updatedAt: timestamp(parsed.cveMetadata.dateUpdated), origin: "User-supplied CVE Record; authenticity not verified" } };
}
function nuclei(items) {
    const findings = [], groups = new Map();
    let skipped = 0, grouped = 0;
    for (const [index, row] of items.entries()) {
        if (row["matcher-status"] === false || row.error) {
            skipped++;
            continue;
        }
        if (row.type !== undefined && row.type !== "http")
            throw Error(`Observation ${index + 1} uses an unsupported protocol. This workflow currently accepts HTTP Nuclei results only.`);
        const info = row.info;
        if (!record(info) || !string(row["template-id"], 160) || !string(info.name))
            throw Error(`Observation ${index + 1} needs template-id and info.name from a Nuclei result.`);
        const rule = string(row["template-id"], 160), asset = assetLabel(row["matched-at"] ?? row.host ?? row.url), matcher = string(row["matcher-name"], 100);
        const ids = cveIds(record(info.classification) ? info.classification["cve-id"] : undefined);
        const severityValue = string(info.severity).toLowerCase();
        const severity = ["critical", "high", "medium", "low", "info"].includes(severityValue) ? severityValue : "unknown";
        const key = JSON.stringify([rule, asset, matcher, ids, severity]), previous = groups.get(key);
        if (previous) {
            const observed = timestamp(row.timestamp);
            if (observed) {
                previous.observedAt = !previous.observedAt || observed > previous.observedAt ? observed : previous.observedAt;
                previous.firstObservedAt = !previous.firstObservedAt || observed < previous.firstObservedAt ? observed : previous.firstObservedAt;
            }
            previous.occurrences++;
            grouped++;
            continue;
        }
        const finding = { id: `finding-${findings.length + 1}`, asset, title: string(info.name), rule, severity, state: "Needs review", cves: ids,
            evidence: `Imported positive result${matcher ? ` (${matcher})` : ""}. Grouped by template, service origin, matcher, CVE IDs and reported severity.`,
            recommendation: "Verify the original evidence, affected product and applicability before opening remediation work. An imported match does not confirm exploitability.",
            occurrences: 1, observedAt: timestamp(row.timestamp), firstObservedAt: timestamp(row.timestamp), kev: unknownKev() };
        findings.push(finding);
        groups.set(key, finding);
    }
    return { findings, skipped, grouped };
}
function httpBaseline(items) {
    const findings = [];
    for (const [index, row] of items.entries()) {
        const asset = assetLabel(row.url ?? row.asset), headers = row.headers;
        if (!record(headers) && !Array.isArray(headers))
            throw Error(`Observation ${index + 1} needs a headers object or an array of {name, value} entries.`);
        const values = new Map();
        const entries = Array.isArray(headers) ? headers.map(h => { if (!record(h) || typeof h.name !== "string" || typeof h.value !== "string")
            throw Error(`Observation ${index + 1} contains an invalid header entry.`); return [h.name, h.value]; }) : Object.entries(headers).flatMap(([key, value]) => { const list = Array.isArray(value) ? value : [value]; if (list.some(v => typeof v !== "string"))
            throw Error(`Observation ${index + 1} has a non-text header value.`); return list.map(v => [key, v]); });
        if (entries.length > 200)
            throw Error(`Observation ${index + 1} exceeds 200 header entries.`);
        for (const [key, value] of entries) {
            const name = key.trim().toLowerCase();
            if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name) || value.length > 16384)
                throw Error(`Observation ${index + 1} has an invalid header name or an oversized value.`);
            values.set(name, [...(values.get(name) ?? []), value.trim()]);
        }
        const sourceUrl = string(row.url ?? row.asset, 2048), scheme = /^https?:\/\//i.test(sourceUrl) ? new URL(sourceUrl).protocol : null;
        const add = (rule, title, state, evidence, recommendation) => findings.push({ id: `finding-${findings.length + 1}`, asset, title, rule, severity: state === "Needs review" ? "low" : "info", state, cves: [], evidence, recommendation, occurrences: 1, observedAt: timestamp(row.observedAt), firstObservedAt: timestamp(row.observedAt), kev: unknownKev() });
        const hsts = values.get("strict-transport-security") ?? [], ages = hsts.map(v => v.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i));
        const validHsts = hsts.length === 1 && ages[0] && Number.isSafeInteger(Number(ages[0][1])) && Number(ages[0][1]) > 0 && (hsts[0].match(/\bmax-age\s*=/gi) ?? []).length === 1;
        add("spectyn.hsts.v1", "HTTPS transport policy", scheme === null ? "Not assessable" : scheme !== "https:" ? "Not applicable" : validHsts ? "Observed" : "Needs review", scheme === null ? "The supplied asset has no scheme." : scheme !== "https:" ? "HSTS is evaluated only on HTTPS responses." : !hsts.length ? "No HSTS header was supplied." : validHsts ? "One HSTS policy with a positive max-age was supplied." : "The supplied HSTS policy is duplicated, disabled or lacks a valid positive max-age.", "Review the service's HTTPS policy and approved HSTS configuration. Presence alone does not establish policy strength.");
        const contentTypes = values.get("content-type") ?? [], html = contentTypes.some(v => ["text/html", "application/xhtml+xml"].includes(v.split(";")[0].trim().toLowerCase())), csp = values.get("content-security-policy") ?? [], reportOnly = values.has("content-security-policy-report-only");
        add("spectyn.csp.v1", "HTML content policy", contentTypes.length !== 1 ? "Not assessable" : !html ? "Not applicable" : csp.some(v => v.length > 0) ? "Observed" : "Needs review", !contentTypes.length ? "No content type was supplied." : contentTypes.length > 1 ? "Multiple content types were supplied; the response context needs review." : !html ? "The supplied content type is not HTML." : csp.some(v => v.length > 0) ? "An enforced CSP header was supplied; directives have not been assessed." : reportOnly ? "Only a report-only CSP header was supplied." : "No enforced CSP header was supplied.", "Review an application-appropriate content policy. Report-only policies do not enforce browser restrictions.");
        const nosniff = values.get("x-content-type-options") ?? [];
        add("spectyn.nosniff.v1", "Content-type handling", nosniff.length === 1 && nosniff[0].toLowerCase() === "nosniff" ? "Observed" : "Needs review", !nosniff.length ? "No X-Content-Type-Options header was supplied." : nosniff.length === 1 && nosniff[0].toLowerCase() === "nosniff" ? "The supplied value is nosniff." : "The supplied header is duplicated or differs from nosniff.", "Confirm the intended response headers in the service configuration and review the original capture.");
    }
    return { findings, skipped: 0, grouped: 0 };
}
export function runEvidenceWorkflow(workflow, input, kevInput = "", sample = false) {
    if (!evidenceRecipes.some(recipe => recipe.id === workflow))
        throw Error("Unknown evidence workflow.");
    const items = rows(input), assessment = workflow === "cve-applicability" ? applicability(items, kevInput) : null, result = assessment ?? (workflow === "http-baseline" ? httpBaseline(items) : nuclei(items));
    if (workflow === "http-baseline" && !items.length)
        throw Error("Supply at least one HTTP observation.");
    const kev = workflow === "kev-match" ? catalog(kevInput) : null;
    if (kev)
        for (const finding of result.findings) {
            const ids = finding.cves.filter(id => kev.ids.has(id));
            finding.kev = { state: ids.length ? "Listed" : finding.cves.length ? "Not listed in supplied catalog" : "Unknown", ids };
        }
    return { schemaVersion: 1, ruleset: "spectyn-evidence/1.0", workflow, completedAt: new Date().toISOString(), inputRecords: items.length, groupedRecords: result.grouped, skippedRecords: result.skipped, sample, catalog: kev?.metadata ?? null, findings: result.findings, ...(assessment ? { advisory: assessment.advisory } : {}) };
}
export const inventoryExample = JSON.stringify([{ asset: "https://preview.example.com", vendor: "Example vendor", product: "Example service", version: "2.4.0", source: "Fictional inventory export", observedAt: "2026-09-18T10:00:00Z" }, { asset: "https://app.example.com", vendor: "Example vendor", product: "Example service", version: "2.5.0", source: "Fictional inventory export", observedAt: "2026-09-18T10:00:00Z" }], null, 2);
export const advisoryExample = JSON.stringify({ dataType: "CVE_RECORD", dataVersion: "5.1", cveMetadata: { cveId: "CVE-2099-10000", state: "PUBLISHED", dateUpdated: "2026-09-18T09:00:00Z" }, containers: { cna: { affected: [{ vendor: "Example vendor", product: "Example service", versions: [{ version: "2.4.0", status: "affected" }, { version: "2.5.0", status: "unaffected" }] }] } } }, null, 2);
export const nucleiExample = JSON.stringify([
    { "template-id": "sample-product-advisory", info: { name: "Sample product advisory candidate", severity: "high", classification: { "cve-id": ["CVE-2024-27199"] } }, host: "https://preview.example.com", "matcher-status": true, timestamp: "2026-09-17T10:00:00Z" },
    { "template-id": "sample-header-review", info: { name: "Sample response-header observation", severity: "info" }, host: "https://app.example.com", "matcher-status": true },
], null, 2);
export const headerExample = JSON.stringify([{ url: "https://app.example.com", observedAt: "2026-09-17T10:00:00Z", headers: { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy-Report-Only": "default-src 'self'", "X-Content-Type-Options": "nosniff" } }], null, 2);
export const kevExample = JSON.stringify({ catalogVersion: "sample-fixture", dateReleased: "2026-09-17", vulnerabilities: [{ cveID: "CVE-2024-27199" }] }, null, 2);
