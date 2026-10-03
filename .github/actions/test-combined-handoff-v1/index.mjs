/** Remove unused injected credentials before exercising synthetic private proof integration. */
for (const name of ['ARMORER_WORKFLOW_READ_TOKEN', 'ACTIONS_RUNTIME_TOKEN']) delete process.env[name];
await import('../../../tests/combined_handoff_join_cases_v1.mjs');
