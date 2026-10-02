# Selected Cargo graph v2 development fixtures

These synthetic metadata/compiler fixtures exercise the Python writer and the independent Rust consumer semantics. They are not signed evidence, source approval or Build L2 acceptance. The fixture context is independently fixed in the tests: fixture/graph, source a repeated40, workflow b repeated40, run17/attempt2, config/lock/Cargo-lock digests 1/2/3 repeated64. The optional case retains a feature-activated dependency and a host build dependency; minimal excludes the optional workspace-unified edge; the zero-dependency library has a custom target name. The host dependency uses a prerelease version to preserve legitimate dependency versions.

No fixture artifact is executed and no publication/tag operation is available to these semantic tests. Real complete-release authentication and native producer integration remain separate gates.
