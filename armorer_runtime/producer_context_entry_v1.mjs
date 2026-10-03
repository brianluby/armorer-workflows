/** Fixed fresh-process worker; only the Python launcher supplies its sterile environment and stdin. */
import { authenticateProducerContext, producerContextRecord } from './producer_oidc_worker_v1.mjs';
import { authenticateMappedProducerContext, mappedProducerContextRecord } from './mapped_producer_worker_v1.mjs';

let cancelled = false;
/** Cancellation discards any eventual proof; mapped native children also receive this signal. */
function cancel() { cancelled = true; }
process.on('SIGTERM', cancel);
try {
  let size = 0;
  const blocks = [];
  for await (const block of process.stdin) {
    size += block.length;
    if (size > 2 * 1024 * 1024) throw new Error('input-bound');
    blocks.push(block);
  }
  const input = JSON.parse(Buffer.concat(blocks, size));
  if (!input || Object.keys(input).sort().join(',') !== 'intent,operation,schema_version' || input.schema_version !== 1 ||
    !['oidc', 'mapped'].includes(input.operation) || cancelled) throw new Error('input-invalid');
  const proof = input.operation === 'oidc' ? await authenticateProducerContext(input.intent) :
    await authenticateMappedProducerContext(input.intent);
  if (cancelled) throw new Error('cancelled');
  const observation = input.operation === 'oidc' ? producerContextRecord(proof) : mappedProducerContextRecord(proof);
  // This JSON is an audit observation, never a portable permit for signing or publication.
  process.stdout.write(JSON.stringify({ schema_version: 1, operation: input.operation, observation,
    startup_environment_isolated: true, production_node_catalog_accepted: false,
    signing_authorized: false, publication_authorized: false }));
} catch {
  process.exitCode = 1;
} finally {
  process.removeListener('SIGTERM', cancel);
}
