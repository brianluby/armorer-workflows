/** Join qualification archive measurements to an original private writer observation. */
import { artifactWriterRecord } from '../armorer_runtime/artifact_writer_worker_v1.mjs';

/** Return only copied audit evidence after matching all eighteen measured qualification archives. */
export function joinArchives(collection, proof) {
  const writer = artifactWriterRecord(proof);
  const requireCondition = value => {
    if (!value) throw new Error('combined-native-qualification-denied');
  };
  requireCondition(collection.state === 'combined-build-policy-transport-observed' && collection.qualification_only === true &&
    collection.authentication_mode === 'isolated-workflow-token' && collection.archive_bytes_verified === true &&
    collection.repository === writer.expected.repository && collection.repository_id === writer.expected.repository_id &&
    collection.head_commit === writer.expected.head_sha && collection.run_id === writer.expected.run_id &&
    collection.run_attempt === writer.expected.run_attempt &&
    Object.keys(collection.artifacts).length === 18 && writer.snapshot.artifacts.length === 18);
  for (const { artifact } of writer.snapshot.artifacts) {
    const read = collection.artifacts[artifact.name];
    requireCondition(read && String(read.provider.id) === artifact.id &&
      Number.isSafeInteger(read.archive.size) && read.archive.size > 0 &&
      String(read.archive.size) === artifact.size && read.provider.size_in_bytes === read.archive.size &&
      `sha256:${read.archive.sha256}` === artifact.digest && read.provider.name === artifact.name &&
      read.provider.created_at === artifact.created_at);
  }
  return writer;
}
