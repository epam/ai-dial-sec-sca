# Changelog

## v0.8.1

`report.json` stays at `schema_version` 4; the two new fields are additive and appended at the end of a record. Without them the report is the v0.8.0 report byte for byte.

### Added

- `versions[].vulns[].upgrades`: per installed version of a record, the target version by the rule of the fix plan, or the `reason` there is none (`needs_major`, `no_fixed_version`, `version_unparsable`, `image_rebuild`).
- `versions[].vulns[].dev_state`: `fixed`, `removed`, `open` or `incomplete`, the state `sca_fix_plan.classify` gives; `null` on development records and without a development version.
- `actions/sca_rules`: an installable package with the rules the engine and the fixer share (package key, version order, upgrade target, fixed-in-development state). `sca_fix_plan` needs it installed next to it and fails at import with a message when it is missing; the actions put it on `PYTHONPATH`.
- `result.json` of `sca_fix_apply`: `pr.number`, `pr.base` and `pr.url` (null without a pull request, always present); the file is documented as the contract for consumers (README).

### Changed

- Calendar versions (the first component has four digits or more, for example `2024.8.30`) have no major: a newer year is a normal upgrade, not `needs_major`. Two-digit years (`24.1`) keep the semver major.
- `upgrades`: with development evidence (development fixes every record of the package that contains the installed version) every record of the package gets the group's target; without it a record with no fixed version above the installed version has `no_fixed_version`. It is the package-wide fact over all records with `allow-major` none; the plan can differ. Computed once per package and installed version (a package with 1000 records takes well under a second).

- The target rule: a target taken from the fixed versions must not be vulnerable to any other record of the package (it is at or above the highest fixed version of each record, at or above a fixed version of its own major.minor, or at or above the highest fixed version of its own major, so a record with one fix per major does not block a valid target of the major); a development version is the target as before; versions that compare equal (`1.2`, `1.2.0`) are chosen by the spelling with as many components as the installed version, then by text, the same on every run. The plan can differ from v0.8.0 for a package whose records are fixed on different branches.
- The development data of a record must be complete in each kind of target the record was found in: a library found only in an image is judged by the development image of the same image, not by the source scan; a library with a source target needs the development sources only, as before. A library found only in an image is now `development_data_incomplete` when the development image scan failed.
- The package key, the version order, the target rule and the development state live once in `sca_rules`; `sca_fix_plan.versions` is gone (its names are in `sca_rules`).

## v0.8.0

`report.json` stays at `schema_version` 4. Every change to it is additive (new optional fields); no field is renamed, retyped or removed. Without the new inputs the report differs from v0.7.0 only by the new fields and by one intended change: the `.trivyignore` rule of a scan-tag run (see Changed).

### Added

- `sca_merge_results`: optional input `engine-ref` (also the environment variable `SCA_ENGINE_REF` and the argument `--engine-ref`) sets the `engine` of the report. Order: argument, environment variable, the ref the action runs from, else `null`.
- `sca_query_osv`: optional input `offline-db-dir`. Given, osv-scanner runs both scans with `--offline` against the databases the caller downloaded (the engine never downloads them). A `no offline version of the OSV database` message on stderr fails the target whatever the exit code. A target may carry `image_scan_disabled_reason`, shown as the reason of the skipped OSV image scan.
- Acceptance rules of the caller: the optional `acceptances` list of `targets.json` marks the matching findings (`accepted`: `{until, reason, rule}`) and records (`accepted`: `{until}`), and `report.json` gets `acceptances[]` with `expired`, `bad_expiry` and `matched` per rule.
- `version_kinds` of `targets.json`: the kind of a version from the caller (`development`, `release`, `candidate`) for refs that are not semver tags. For a mapped version `latest` follows `kind == "release"`.
- `versions[].role` (`dev`, `rc`, `rel`, `rel-1` or `null`).
- `pkg_key` on `versions[].vulns[]` and `versions[].packages[]`: the normalized package name the engine groups by.
- `src_pkg` on `versions[].vulns[]` and `versions[].packages[]`: the Trivy source package of an OS package.
- `title` on `versions[].vulns[]`: the Trivy title, else the OSV summary.
- `summary` and `src_pkg` on `findings[]`: the OSV summary (`null` for Trivy) and the Trivy `SrcName` (`null` otherwise).
- The fixer: the actions `sca_fix_plan` (fix plan, schema 2) and `sca_fix_apply` (Dependabot CLI, npm override, opt-in base image bump, proof by rescan, one pull request per release line), and `records_of` in `sca_merge_results` so the applier builds records the way the report does.
- `sca_query_osv` and `_install_trivy`: optional input `trivy-sha256`, the sha256 of the Trivy release archive of the runner's architecture, for a `trivy-version` that has no pinned value in the engine (pinned: `v0.75.0`, Linux-64bit and Linux-ARM64). `trivy-version` must have the form `vX.Y.Z`; anything else fails with an error.
- `acceptances[].bad_rule`: a rule of the wrong shape (see the README) is kept with `bad_rule: true`, never acts and does not stop the report; the summary lists such rules.
- `sca_fix_plan.upgrade_target(installed, records, dev_versions=(), allow_major="none")`: the public form of the plan's target rule, returning `(target, evidence, reason_code)`.

### Changed

- The `.trivyignore` of the only source target is read when the run has no default-branch source (a run whose source is a version). When a line and an acceptance rule name the same vulnerability, the earliest `until` wins.
- Intended change, without a new input: in a scan-tag run (the only source target is a tag, not the default branch) the `.trivyignore` of that tag is read and marks the records, as described in the previous item; the golden report `report_scan_tag.json` records it. Consumers of `ignores` and `ignores_error` see the tag's file there.
- `ignores_error` is `null` for a run without any source target (images only); it was an error text.
- `summary.md`: a row lists at most 5 vulnerability ids and then `+N more`, and a commit shared by several source targets is listed once under `Seen in`. `report.json` is not affected.
- Trivy is installed from the aquasecurity/trivy GitHub release of `trivy-version` (sha256 of the archive pinned per version in the engine, else `trivy-sha256`; cached by version, OS and architecture; the cached archive is verified again on every run) instead of `aquasecurity/setup-trivy`, which downloaded from `get.trivy.dev`.
- ORAS CLI 1.3.4 (was 1.3.3) and `oras-project/setup-oras` v2.0.3 in `sca_resolve_targets`.

### Fixed

- A Trivy title that is JSON `null` no longer crashes the merge.
- Two refs of one version mapped to different kinds in `version_kinds` is an input error (`ValueError` naming both refs) instead of the first one winning.
- A malformed acceptance rule (a string `targets`, string `ids`, missing `package`) no longer crashes the merge or matches by substring.
- A Trivy install no longer fails on a cache miss when `get.trivy.dev` does not resolve.
