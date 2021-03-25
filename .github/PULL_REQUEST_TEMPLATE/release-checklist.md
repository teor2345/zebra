---
name: Release Checklist Template
about: Checklist of versioning to create a taggable commit for Zebra
title: ''
labels:
assignees: ''

---

## Versioning

### Which Crates to Increment

To check if any of the top-level crates need version increments, go to the zebra GitHub code page: https://github.com/ZcashFoundation/zebra. `git diff --stat <previous-release-tag> origin/main` is also useful to see
what's changed.

- [ ] Increment the crates that have new commits since the last version update
- [ ] Increment any crates that depend on crates that have changed
- [ ] Use the `zebrad` crate version in the `zebrad` app code and `zebra-network` user agent
- [ ] Use the latest git tag in `README.md`

### How to Increment Versions

Zebra follows [semantic versioning](https://semver.org).

Semantic versions look like: `MAJOR`.`MINOR`.`PATCH[`-`TAG`.`PRE-RELEASE]`

#### Pre-Release Crates

Pre-Release versions have a `TAG` like "alpha" or "beta". For example: `1.0.0-alpha.0`

1. Increment the `PRE-RELEASE` version for the crate.

Optionally, if a `MINOR` feature pre-release breaks `MAJOR` API compatibility:

2. Increment the `MAJOR` version, and reset all the other versions to zero

#### Unstable Crates

Unstable versions have a `MAJOR` version of zero. For example: `0.1.0`

1. Follow stable crate versioning, but increment the `MINOR` version for breaking changes

#### Stable Crates

For example: `1.0.0`

Increment the first version component in this list, and reset the other components to zero:
1. MAJOR versions for breaking public API changes and removals
    * check for types from dependencies that appear in the public API
2. MINOR versions for new features
3. PATCH versions for bug fixes
    * includes dependency updates that don't impact the public API

### Version Locations

Once you know which versions you want to increment, you can find them in the:
- [ ] zebra* `Cargo.toml`s
- [ ] tower-* `Cargo.toml`s
- [ ] `zebrad` app code: https://github.com/ZcashFoundation/zebra/blob/main/zebrad/src/components/tracing/component.rs
- [ ] `zebra-network` protocol user agent: https://github.com/ZcashFoundation/zebra/blob/main/zebra-network/src/constants.rs
- [ ] `README.md`
- [ ] `Cargo.lock`: automatically generated by `cargo build`

Merge all these version increments as one commit, by squashing and rebasing the PR onto the main branch.

#### Version Tooling

You can use `fastmod` to interactively find and replace versions.

For example, for `zebra-1.0.0-alpha-3`, we did:
```
fastmod --extensions rs,toml,md --fixed-strings '1.0.0-alpha.3' '1.0.0-alpha.4'
fastmod --extensions rs,toml,md --fixed-strings '1.0.0-alpha.2' '1.0.0-alpha.3'
fastmod --extensions rs,toml,md --fixed-strings '0.2.0' '0.2.1' tower-batch
```

We skipped `tower-fallback`, because it hadn't changed since the last tag.

## Initial Testing

- [ ] After any changes, test that the `cargo install` command in `README.md` works (use `--path` instead of `--git` locally)

## Change Log

**Important**: Any merge into `main` deletes any edits to the draft changelog. Edit the draft changelog in a pad like https://pad.riseup.net

We follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format.

We use [the Release Drafter workflow](https://github.com/marketplace/actions/release-drafter) to automatically create a [draft changelog](https://github.com/ZcashFoundation/zebra/releases).

To create the final change log:
- [ ] Copy the draft changelog into a pad like https://pad.riseup.net
- [ ] Delete any trivial changes
- [ ] Combine duplicate changes
- [ ] Edit change descriptions so they are consistent, and make sense to non-developers
- [ ] Check the category for each change
  - prefer the "Fix" category if you're not sure

#### Change Categories

From "Keep a Changelog":
* `Added` for new features.
* `Changed` for changes in existing functionality.
* `Deprecated` for soon-to-be removed features.
* `Removed` for now removed features.
* `Fixed` for any bug fixes.
* `Security` in case of vulnerabilities.

## After merging this PR
- [ ] Check for any PRs that have been merged since you created the changelog pad
- [ ] Update the draft release with the final changelog
- [ ] Set the release title to `Zebra ` followed by the version tag, for example: `Zebra 1.0.0-alpha.0` 
- [ ] Set the tag name to the version tag, for example: `1.0.0-alpha.0`
- [ ] Set the release to target the `main` branch
- [ ] Mark the release as 'pre-release' (until we are no longer alpha/beta)

## Final Testing

- [ ] After tagging the release, test that the exact `cargo install` command works
      (`--git` behaves a bit differently to `--path`)

If the build fails after tagging:
1. fix the build
2. check if the fixes changed any extra crates, and do the required version increments
3. update `README.md` with a **new** git tag
4. tag a **new** release