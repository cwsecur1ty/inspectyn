import { runEvidenceWorkflow } from './evidence-workflows.mjs';

export { evidenceRecipes, EVIDENCE_LIMIT, CATALOG_LIMIT } from './evidence-workflows.mjs';

// Preserve the source's review states when adapting findings to the CLI schema.
export function reviewEvidence(workflow, input, supplement = '') {
  const original = runEvidenceWorkflow(workflow, input, supplement);
  const findings = original.findings.map((finding) => ({
    id: finding.id,
    ruleId: finding.rule,
    severity: finding.severity,
    title: finding.title,
    evidence: finding.evidence,
    remediation: finding.recommendation,
    target: finding.asset,
    state: finding.state,
    cves: finding.cves,
    occurrences: finding.occurrences,
    observedAt: finding.observedAt,
    firstObservedAt: finding.firstObservedAt,
    kev: finding.kev,
  }));

  return {
    schemaVersion: 1,
    tool: { name: 'inspectyn', version: '0.2.0' },
    kind: 'review',
    generatedAt: original.completedAt,
    complete: findings.every((finding) => finding.state !== 'Not assessable'),
    targets: [...new Set(findings.map((finding) => finding.target))],
    findings,
    errors: [],
    context: {
      workflow: original.workflow,
      ruleset: original.ruleset,
      inputRecords: original.inputRecords,
      groupedRecords: original.groupedRecords,
      skippedRecords: original.skippedRecords,
      sample: original.sample,
      catalog: original.catalog,
      advisory: original.advisory ?? null,
    },
  };
}
