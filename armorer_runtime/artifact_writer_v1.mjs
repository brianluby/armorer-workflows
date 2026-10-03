/** Retired Node-first interface: supported credentialed readers require the fixed isolated launcher. */
export async function observeArtifactWriters(_offered) {
  throw new Error('artifact-writer-startup-boundary-required');
}
/** Serialized observations never recreate the private worker proof. */
export function artifactWriterRecord(_offered) {
  throw new Error('artifact-writer-observation-denied');
}
