# Experimental garak plan connector

Status: **Harness 1.7.0 release candidate API**, not included in published Harness 1.6.0.
This is an independent Harness integration, not an official NVIDIA component or an
integration endorsed by garak maintainers. It adds no garak dependency to Harness.

## Purpose and trust boundary

The JSON tool-plan proposal in [garak #1841](https://github.com/NVIDIA/garak/issues/1841)
and [PR #2224](https://github.com/NVIDIA/garak/pull/2224) asks a model for a plan and
checks names/ordered sequences. This connector consumes that **declared plan shape**,
not arbitrary garak reports, arbitrary providers or all tool-call formats.

```text
one untrusted plan ─┬─ garak detector → observation only
                   └─ strict adapter → Quarantine → Gateway → built-in synthetic operation
```

The adapter never receives a detector score, calls a model, changes policy, imports
garak, or dispatches. Application-owned configuration selects the profile and exact
tool-alias/capability mapping. Application code owns the request id. The model cannot
choose a protocol, profile, policy, executor, approval, or wider capability list.
Normalization is not admission; admission is not authorization; authorization is not
execution evidence. A garak score of `0.0` is not permission. In the selected upstream
detector it can also mean that no valid JSON plan was found.

## Python API

Import explicitly from `agentic_security_harness.garak_plan_adapter`:

```python
from agentic_security_harness.garak_plan_adapter import (
    GarakPlanAdapterConfigV1, GarakToolBindingV1, normalize_garak_plan_v1,
)

config = GarakPlanAdapterConfigV1(
    profile_id="example.garak",
    profile_version="1",
    bindings=(GarakToolBindingV1(
        tool_name="synthetic.lookup", capability_id="bounded.lookup",
    ),),
)
normalized = normalize_garak_plan_v1(
    b'{"tool_calls":[{"tool":"synthetic.lookup","args":{"key":"project-status"}}]}',
    config=config,
    request_id="example:1",
)
# normalized.outcome is content-free metadata. normalized.envelope is untrusted
# candidate bytes, NOT a permission or a public raw-data artifact.
```

Pass candidate bytes to the separately configured
[`evaluate_quarantine_input_v1`](quarantine-connector.md). The registry must declare
the selected profile and capability. Only an admitted request may reach the fixed
Gateway policy. No new per-request policy/scope mechanism is introduced.

Inputs are at most 16,384 bytes and eight nested containers. The only root key is
`tool_calls`. An empty list explicitly means no request; one call requires exactly
`tool` and `args`. Multiple calls are rejected, with no partial execution. Duplicate
keys, nonfinite numbers, invalid UTF-8/surrogates, text wrappers, extra fields, wrong
types and unknown aliases are rejected. Decimal/exponent numbers are rejected if
the emitted JSON would change their decimal value through floating-point rounding
or underflow; notation may change (for example, `1e1` to `10.0`). Whitespace can be normalized; missing or
incorrect values are never repaired. Argument values remain untrusted and are checked
again by Quarantine/Gateway. Caller configuration errors raise a fixed adapter error;
untrusted input rejection produces a typed outcome without the raw input.

## Reproducible example and exact compatibility

See [the example](../examples/garak-gateway/README.md), its fixed public-synthetic corpus,
manifest and independent stdlib checker. The example records an allowed constant lookup,
a forbidden/unregistered tool, unparseable text, and an invalid argument. It records
detector outcome, normalization, admission, Gateway reason and execution count separately.

The optional source-detector lane pins garak
`ac4c5567f0c17834aace52b14788c1ca3548738b` (PR #2224, **unmerged at selection**), archive
and extracted package-tree hashes. It imports and invokes the real named detector with
its small declared import dependency set; this is **not** a complete garak distribution
installation or a claim about a released garak version. No detector code is copied into
Harness and no unknown plugins, model packages or weights are loaded.

The runner installs an early Python audit hook denying network/process events and
restricting reads/writes. garak's import-time configuration directories and log are
redirected into a fresh scratch directory, with inherited provider/user configuration
discarded. Only Windows `SystemRoot` is retained for native dependencies. Those setup
writes are counted separately; zero external tool dispatch is not zero filesystem I/O.
The hook is not an OS sandbox and does not prove native-code containment. CI uses fresh
Linux/Windows runners; only the content-free report is uploaded, not scratch logs.

## License, attribution and non-claims

Harness and the selected garak source use Apache-2.0. The example links to garak and
uses its name only to identify compatibility. No NVIDIA/garak logo, endorsement or
affiliation is implied. No upstream source is vendored or modified; downloaded source
retains its LICENSE/NOTICE files. Future redistribution/modification must preserve the
applicable license and notices. See [garak's license](https://github.com/NVIDIA/garak/blob/ac4c5567f0c17834aace52b14788c1ca3548738b/LICENSE)
and [contribution rules](https://github.com/NVIDIA/garak/blob/main/CONTRIBUTING.md).
An upstream PR would be a separate contribution requiring their process and acceptance.

This feature does not establish detector accuracy, model intent, general prompt-injection
resistance, authenticated custody, replay protection, multi-call sequence enforcement,
arbitrary tool execution, production security or independent human review. Hashes bind
local observations; they do not authenticate a producer. Synthetic fixture results are
not live-model results. Published 1.6.0 and prior sealed model campaigns are unchanged.
