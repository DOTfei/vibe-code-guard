const { AI_REVIEW_SCHEMA_VERSION, modelMetadata } = require('./review-schema');

class DisabledProvider {
  constructor(reason = 'AI review is disabled until an explicit provider is configured.') {
    this.name = 'disabled';
    this.model = 'none';
    this.reason = reason;
  }

  async availability() { return { available: false, reason: this.reason }; }
}

class UnavailableProvider {
  constructor(name, reason) {
    this.name = name;
    this.model = 'unconfigured';
    this.reason = reason;
  }

  async availability() { return { available: false, reason: this.reason }; }
}

class MockProvider {
  constructor(model = 'synthetic-v0.4') {
    this.name = 'mock';
    this.model = model;
  }

  async availability() { return { available: true, reason: 'Synthetic provider enabled explicitly for local testing.' }; }

  async reviewFinding(context) {
    const finding = context.finding;
    const priority = finding.severity === 'CRITICAL' ? 'P0' : finding.severity === 'HIGH' ? 'P1' : finding.severity === 'MEDIUM' ? 'P2' : 'P3';
    return {
      schemaVersion: AI_REVIEW_SCHEMA_VERSION,
      findingId: finding.id,
      generatedAt: new Date().toISOString(),
      model: modelMetadata(this.name, this.model),
      summary: `Synthetic advisory review for ${finding.title}.`,
      plainLanguageExplanation: `The deterministic scanners grouped evidence for this ${finding.category} issue at the recorded location.`,
      whyItMatters: `The issue is ${finding.severity} according to scanner evidence and should be reviewed before release decisions rely on it.`,
      impact: { scope: 'The affected scope must be confirmed from the listed location and project stack.', likelyAffectedAreas: context.project.stack.slice(0, 5), confidence: 'MEDIUM' },
      priority: { suggested: priority, reason: `Priority is advisory and starts from deterministic severity ${finding.severity}.` },
      remediation: {
        recommendedApproach: 'Inspect the root cause at the reported location, apply the smallest safe fix, and run the relevant scanner again.',
        steps: ['Confirm the finding in the listed code or dependency context.', 'Apply a targeted remediation without disabling security controls.', 'Run the relevant scanner and review the resulting lifecycle state.'],
        verificationAdvice: 'Only a successful relevant rescan and the deterministic lifecycle engine can establish verification.',
      },
      falsePositiveAssessment: { likelihood: 'UNKNOWN', reason: 'The synthetic provider cannot decide this without additional user-confirmed context.', requiresUserDecision: true },
      uncertainties: ['Exploitability and runtime reachability were not established by this advisory review.'],
      questions: ['Is the affected path reachable across the intended authentication boundary?'],
      evidenceReferences: context.scannerEvidence.slice(0, 8).map((observation) => ({
        scanner: observation.scanner,
        files: observation.location.file ? [observation.location.file] : [],
        vulnerabilityIds: observation.identity.vulnerabilityId ? [observation.identity.vulnerabilityId] : [],
      })),
    };
  }

  async reviewRunSummary(context) {
    const blockers = context.findings.filter((finding) => ['CRITICAL', 'HIGH'].includes(finding.severity) && ['OPEN', 'FIXED', 'REOPENED'].includes(finding.status));
    return {
      schemaVersion: AI_REVIEW_SCHEMA_VERSION,
      mode: context.mode,
      generatedAt: new Date().toISOString(),
      model: modelMetadata(this.name, this.model),
      summary: blockers.length ? `${blockers.length} deterministic blocker${blockers.length === 1 ? '' : 's'} require review before release.` : 'No deterministic Critical/High blocker was identified in the supplied run context.',
      blockers: blockers.slice(0, 8).map((finding) => ({ findingId: finding.id, reason: `${finding.severity} ${finding.status} finding remains in the release-gate evidence.` })),
      priorityActions: context.findings.slice(0, 8).map((finding) => ({ findingId: finding.id, action: 'Review scanner evidence and follow the deterministic lifecycle workflow.' })),
      uncertainties: ['This is advisory text; it does not establish exploitability or change the release gate.'],
      questions: ['Which remaining blocker has the highest production exposure?'],
    };
  }
}

function createProvider({ name = process.env.SECURITY_AI_PROVIDER || 'disabled', model = process.env.SECURITY_AI_MODEL } = {}) {
  const provider = String(name || 'disabled').trim().toLowerCase();
  if (provider === 'mock') return new MockProvider(model || 'synthetic-v0.4');
  if (provider === 'local') return new UnavailableProvider('local', 'No local model adapter is configured; no code was uploaded.');
  if (provider === 'external') return new UnavailableProvider('external', 'No external provider adapter is configured; no code was uploaded.');
  return new DisabledProvider();
}

module.exports = { DisabledProvider, MockProvider, UnavailableProvider, createProvider };
