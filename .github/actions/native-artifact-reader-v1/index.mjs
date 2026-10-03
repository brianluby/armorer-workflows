/** Runner-injected runtime scope is received only behind the fixed composite startup environment. */
import { runNativeQualification } from '../../../armorer_runtime/native_reader_bridge_v1.mjs';
try { await runNativeQualification('artifact-writer'); }
catch { console.error('native-artifact-reader-failed'); process.exitCode = 1; }
