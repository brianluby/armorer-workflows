/** Run the fixed synthetic fixture suite on the Actions runtime without caller inputs or live OIDC. */
console.log(`Producer OIDC protocol fixtures: Node ${process.version}, ${process.platform}/${process.arch}`);
await import('../../../tests/producer_oidc_v1.mjs');
