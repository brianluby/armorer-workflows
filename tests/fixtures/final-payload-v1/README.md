# Final payload conformance fixtures

The two schema files are byte-identical copies from the merged Armorer v1 trust
contracts at the immutable source commit in `source-receipt.json`. They validate
the emitted layout and evidence representation on every test host; they do not
authenticate inputs, bundles, platform reports, policy review or catalog trust.

The tests construct deliberately invalid synthetic signatures and explicitly
retain an unverified result. No synthetic signature or platform record earns
release or SLSA acceptance.
