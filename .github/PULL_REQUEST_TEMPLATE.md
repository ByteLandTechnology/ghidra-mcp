## Summary

<!-- Tell what changed, and why. -->

## Compatibility

<!-- List each change to commands, arguments, responses, config keys, files on
disk or CLI options. If there is no change, write "None". -->

## Verification

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --locked -- -D warnings`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --document-private-items`
- [ ] The runtime checks in CONTRIBUTING.md that apply to this change
- [ ] The Chinese and Japanese translations of each changed document

<!-- Tell which manual checks you did, and on which platforms. -->

## Related issues

<!-- Example: Fixes #123. -->
