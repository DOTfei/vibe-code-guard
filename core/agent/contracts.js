'use strict';

// Stable machine-readable contracts for coding agents. These are independent
// from upstream scanner versions and from the v1 finding schema.
const CLI_SCHEMA_VERSION = '1.0';
const WORKFLOW_VERSION = '0.7.0';
const EXIT_CODES = Object.freeze({ OK: 0, FAILURE: 1, DEGRADED: 2 });

function withContract(data = {}) {
  return { schemaVersion: CLI_SCHEMA_VERSION, workflowVersion: WORKFLOW_VERSION, ...data };
}

module.exports = { CLI_SCHEMA_VERSION, WORKFLOW_VERSION, EXIT_CODES, withContract };
