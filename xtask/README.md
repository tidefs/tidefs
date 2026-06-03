# xtask/

This root hosts non-shipping orchestration helpers.

Current helper:

- `tidefs-xtask` — workspace summary, workspace-policy checker, human terminology map/check helper, and platform scaffold checker

Useful commands when Cargo is available:

```bash
cargo run -p tidefs-xtask -- summary
cargo run -p tidefs-xtask -- check-workspace-policy
cargo run -p tidefs-xtask -- terminology
cargo run -p tidefs-xtask -- check-terminology
cargo run -p tidefs-xtask -- check-platform-scaffolding
cargo run -p tidefs-xtask -- validate-validation-manifest /root/ai/tmp/tidefs-validation/<run-id>/
cargo run -p tidefs-xtask -- check-validation-output-manifests
```
