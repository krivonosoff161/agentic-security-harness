# Extension Distribution Discovery V1

Status: published in the `v1.3.0` Harness core. Publication does not enumerate, install,
trust, import, or activate an optional companion distribution.

This contract closes one narrow installable-extension gap without turning package metadata
into trust. An operator names exactly one distribution, one extension id, one or more
absolute local search roots, and the exact configuration bytes whose digest the extension
manifest declares. Harness inspects only that selection; it does not enumerate candidates
for automatic activation, contact a package index, install dependencies, or import code.

## Controlled sequence

```text
explicit distribution name + extension id + local search roots + configuration bytes
    -> metadata-only installed distribution inspection
    -> exact RECORD/file/entry-point/manifest verification
    -> canonical inspection receipt (code_loaded=false)
    -> operator repeats the exact inspection_id
    -> immediate identical reinspection
    -> canonical approval receipt (code_loaded=false, authority=none)
    -> operator separately constructs an ExtensionV1 object
    -> Harness binds that object's exact manifest pins to the approval
    -> existing explicit StaticExtensionRegistryV1 may register the wrapper
```

The supported entry-point group is fixed to
`agentic_security_harness.extensions.v1`. V1 accepts exactly one entry in that group,
requires its name to equal the extension id, and restricts its value to a single top-level
source module plus one factory attribute. The module itself must be a regular, single-link
file listed in the distribution `RECORD`; package, dotted-module, native-library, link,
Windows-reserved path and already-loaded-module origins fail closed. Entry-point defaults
and every nested or non-file metadata entry are forbidden. V1 also rejects `Requires-Dist`: dependency
provenance is not implemented, so dependency-bearing extensions must wait for a later
contract rather than silently widening the trusted code set.

## What is bound

The inspection receipt contains portable relative paths and SHA-256 bindings for:

- normalized distribution name and exact version from `METADATA`;
- exact `Requires-Python: >=3.11,<3.14` and pure-Python `py3-none-any` wheel metadata,
  matching the current Harness support window on Linux and Windows;
- raw `METADATA`, `WHEEL`, `entry_points.txt` and `RECORD` bytes;
- every non-`RECORD` file declared by the distribution;
- the canonical `ash-extension-manifest.json` in the `.dist-info` directory;
- the single source implementation file;
- caller-supplied configuration bytes, by digest only;
- the extension id/version, Harness API, entry point and all fixed non-claims.

Unknown or duplicate RECORD paths, non-SHA-256 rows, size drift, metadata-directory extras,
files outside the one source module plus `.dist-info`, entry-point extras, duplicate matching
distributions, path links/reparse points and post-inspection drift are rejected. Files are
opened without following links where the platform supports it. Pre/post path metadata is
compared with path metadata, while two independently opened descriptors must have the same
descriptor identity and exact repeated bytes. POSIX keeps the path-stat-to-descriptor-stat
identity binding and `O_NOFOLLOW`. Windows uses native `CreateFileW` with
`FILE_FLAG_OPEN_REPARSE_POINT` and read sharing only for the target and every directory
from the selected root to its parent. Write, delete and rename access is denied while those
handles are open. A final same-path native handle must match the locked first handle's file
id, attributes and bytes, and directory identities plus path topology are rechecked before
any guard is released. This avoids comparing incompatible Windows path-stat and handle-stat
device/inode representations without dropping the regular, single-link, size, reparse,
stable-content or RECORD digest checks. Inspection and approval receipts use closed schemas
and content-derived identities.

The generated contract manifest binds the implementation and its public API, Extension
SDK, portfolio-contract and safe-I/O runtime closure, together with tests, documentation
and the Linux/Windows workflow. A dependency or integration change therefore makes the
committed contract stale until it is regenerated and reviewed.

## Operator API

```python
inspection = inspect_extension_distribution_v1(
    distribution_name="example-extension",
    extension_id="example.security-check",
    search_paths=(site_packages,),
    configuration_bytes=canonical_nonsecret_config,
)

approval = approve_extension_distribution_v1(
    approved_inspection=inspection,
    approved_inspection_id=inspection.inspection_id,
    search_paths=(site_packages,),
    configuration_bytes=canonical_nonsecret_config,
)

# Package construction is deliberately outside the discovery layer.
approved_extension = bind_operator_approved_extension_v1(approval, operator_object)
registry.register(approved_extension)
```

Do not place credentials in configuration bytes for this candidate. The bytes remain in
the caller process and are not serialized, but this slice has no credential broker or
secret-custody contract.

## Trust boundary and non-claims

`RECORD` is self-declared package integrity metadata. Verifying it detects local file drift
relative to that installed metadata; it does not prove who authored or signed the package.
The approval receipt is an operator decision over exact bytes, not a certificate.

The binder verifies that an already constructed object's manifest matches the approved
extension id/version and manifest, implementation and configuration digests. Because
Harness does not import the module, it cannot prove that the supplied object originated
from the inspected file. A dishonest object can lie, and once registered it runs in the
Harness process. The existing Extension SDK run receipt binds the manifest digest but not
the separate distribution approval id, so operators must retain both receipts together.
There is no sandbox, signature, dependency attestation, package allowlist,
download, update, rollback, network, provider, tool, deployment, enforcement or operational
authority in V1.

Synthetic tests create local wheel archives, extract them into isolated roots, and exercise
success, drift, collision, extra-file, unsafe-entry-point, hard-link, reparse, oversize,
descriptor-target swap, canonical-receipt and manifest/configuration mismatch paths. A
dedicated Windows matrix runs the distribution suite on Python 3.11, 3.12 and 3.13.
