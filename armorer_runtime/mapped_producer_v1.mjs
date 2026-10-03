/** The Node-hosted credentialed API is retired; use the isolated Python launcher. */
/** Reject legacy credentialed entry before native reads or any platform credential access. */
export async function authenticateMappedProducerContext(_offered) {
  throw new Error('producer-context-startup-boundary-required');
}
/** Serialized launcher observations and legacy values cannot mint an in-process authority. */
export function mappedProducerContextRecord(_proof) {
  throw new Error('producer-context-unverified-proof');
}
