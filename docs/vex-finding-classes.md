<!-- Generated from aisbom/vex.py by tests/test_vex.py. Do not edit by hand. -->

# AIsbom VEX finding classes

These are **AIsbom finding classes, not CVE identifiers.** They name
categories of content AIsbom detects inside a model file — things that
have no CVE and never will, because the file itself is the payload
rather than a published component with a patchable defect.

They appear as the `vulnerability.name` of an OpenVEX statement and
the `id` of a CycloneDX VEX entry, and resolve under `https://aisbom.io/vex/`.

CVE-keyed statements about a project's Python dependencies are a
separate, additive concern and arrive with OSV mapping; they will join
the same document without changing anything below.

## Compatibility policy

These identifiers outlive the scan that produced them — they sit in
submission folders, CI artifacts and audit archives. If one changed
meaning or vanished, a build gate matching it would stop firing
silently, and a year-on-year comparison would read the change as a
finding resolved and a different one opened.

So the guarantee is **not** that a class is never renamed. It is that
a consumer is never broken:

1. A class is **never deleted**, and an identifier is **never reused**
   for a different meaning.
2. If a class is renamed, its successor carries the old identifier in
   `aliases`, so a rule matching the old string keeps matching.
3. Every identifier ever published is tracked in an append-only list
   in `aisbom/vex.py`, and the test suite fails if any of them stops
   being resolvable. The policy is enforced, not merely stated.

`aliases` carries real CVE identifiers too, where one applies. Both
uses mean the same thing: another name for this same finding.

## Classes

## `AISBOM-PICKLE-RCE`

**Pickle stream imports a code-executing global**

The artifact carries a Python pickle stream whose opcodes import a global that executes code when the stream is deserialized (os.system, subprocess.Popen, builtins.eval and similar). Deserialization is the execution — no separate trigger is needed.

- **Applies to:** gguf, joblib, numpy, onnx, pickle, safetensors
- **Identifier:** https://aisbom.io/vex/AISBOM-PICKLE-RCE
- **Aliases:** none
- **Remediation:** Do not load this file with torch.load/pickle.load. Obtain the model in a non-executable format (SafeTensors) or from a trusted source, and treat the file as active malware rather than as a defective dependency to patch.

## `AISBOM-PICKLE-CODE-OBJECT`

**Serialized Python code objects embedded in the pickle stream**

The pickle stream carries dill-serialized code objects — whole Python functions marshalled into the file. The bytecode is reconstructed on load, so what the model does is not limited to what its declared imports suggest.

- **Applies to:** joblib, numpy, pickle
- **Identifier:** https://aisbom.io/vex/AISBOM-PICKLE-CODE-OBJECT
- **Aliases:** none
- **Remediation:** Do not load this file outside an isolated sandbox. Re-export the model from its source framework so that weights, not code, are what is serialized.

## `AISBOM-PICKLE-UNSCANNED`

**Pickle data present but not fully disassembled**

A pickle stream was found but could not be read to completion — a truncated or malformed stream, an unreadable archive member, or a container AIsbom does not decompress. Absence of a finding here is not evidence of absence: this is the nullifAI evasion class, where a deliberately broken stream is used to end a scan early.

- **Applies to:** joblib, numpy, pickle
- **Identifier:** https://aisbom.io/vex/AISBOM-PICKLE-UNSCANNED
- **Aliases:** none
- **Remediation:** Re-scan the artifact from its original archive, or decompress the container and scan the members individually, before loading it.

## `AISBOM-KERAS-LAMBDA-RCE`

**Keras Lambda layer or marshalled code object executes on load**

The Keras model config declares a Lambda layer or carries a marshalled Python code object. keras.models.load_model reconstructs and can invoke it, so loading the model runs attacker-chosen bytecode.

- **Applies to:** keras
- **Identifier:** https://aisbom.io/vex/AISBOM-KERAS-LAMBDA-RCE
- **Aliases:** none
- **Remediation:** Load with safe_mode=True (Keras 3), or rebuild the layer in your own code and load weights only. Do not load with safe_mode=False or on Keras 2.

## `AISBOM-GGUF-TEMPLATE-INJECTION`

**GGUF chat template contains a sandbox escape or dangerous call**

The Jinja chat template stored in the GGUF metadata contains constructs that reach outside the template sandbox or invoke dangerous callables. The template is evaluated on every inference request, so this executes at serving time rather than at load.

- **Applies to:** gguf
- **Identifier:** https://aisbom.io/vex/AISBOM-GGUF-TEMPLATE-INJECTION
- **Aliases:** none
- **Remediation:** Replace the chat template with one you control, or serve the model through a runtime that does not evaluate the embedded template.

## `AISBOM-ONNX-CUSTOM-OP`

**ONNX graph references operators outside the standard domains**

The graph calls operators that are not part of the standard ONNX domains, so executing it requires loading a third-party operator library. What that library does is outside the model file and outside this scan.

- **Applies to:** onnx
- **Identifier:** https://aisbom.io/vex/AISBOM-ONNX-CUSTOM-OP
- **Aliases:** none
- **Remediation:** Identify and review the operator library the graph requires before running inference, or re-export the model using standard operators.

## `AISBOM-ONNX-EXTERNAL-DATA`

**ONNX tensor data stored outside the model file**

Tensor data is held in separate files referenced by the graph, so the model's weights are not covered by this artifact's hash. A reference that resolves outside the model directory additionally turns loading the model into a read of a file the author chose.

- **Applies to:** onnx
- **Identifier:** https://aisbom.io/vex/AISBOM-ONNX-EXTERNAL-DATA
- **Aliases:** none
- **Remediation:** Scan and pin the external tensor files alongside the model, and reject any reference that resolves outside the model directory.
