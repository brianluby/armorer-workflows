/** The Node-hosted credentialed API is retired; use the isolated Python launcher. */
/** Reject legacy credentialed entry before reading any platform environment or issuing HTTP. */
export async function authenticateProducerContext(_offered) {
  throw new Error('oidc-startup-boundary-required');
}
/** Serialized launcher observations and legacy values cannot mint an in-process authority. */
export function producerContextRecord(_proof) {
  throw new Error('oidc-unverified-proof');
}
