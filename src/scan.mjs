import { validateConfig } from './config.mjs';
import { collectTarget, networkError, CERTIFICATE_ERROR_CODES } from './network.mjs';
import { evaluateObservation } from './checks.mjs';

export async function scan(input, collect = collectTarget) {
  const config = validateConfig(input), findings = [], errors = [], observations = [];
  // One HTTPS request at a time.
  for (const target of config.targets) {
    try {
      const observation = await collect(target,config);
      observations.push(observation);
      findings.push(...evaluateObservation(observation));
      for (const [kind,result] of Object.entries(observation.dns ?? {})) if (result.status === 'error') {
        errors.push({ target,code:'DNS_CHECK_INCOMPLETE',message:`${kind.toUpperCase()} DNS evidence could not be retrieved.` });
      }
    } catch (error) {
      errors.push(networkError(target,error));
      if (CERTIFICATE_ERROR_CODES.has(error.code)) {
        findings.push({ target,ruleId:'SPECTYN_TLS_INVALID',severity:'high',title:'TLS certificate verification failed',
          evidence:networkError(target,error).message,remediation:'Review the certificate hostname, validity and complete chain. Other checks remain incomplete.' });
      }
    }
  }
  return { schemaVersion:1,tool:{name:'inspectyn',version:'0.2.0'},kind:'scan',generatedAt:new Date().toISOString(),
    complete:errors.length === 0 && !findings.some(finding => finding.state === 'Not assessable'),targets:config.targets,findings,errors,observations,
    context:{ dns:config.dns,scope:'Explicit HTTPS URLs only; redirects are not followed.',
      coverage:'One public IP and one HTTPS response per target. No body analysis, crawling, port scan, CVE discovery or exploit verification. DNS mail policy is checked at the exact target hostname only.',
      limits:{maxTargets:20,timeoutMsPerPhase:config.timeoutMs,maxHeaderBytes:32768} } };
}
