# Contributing to Flowsta Signing DNA

Thank you for your interest in contributing to Flowsta! This document provides guidelines for contributing to the Signing DNA repository — the Holochain DNA behind [Sign It](https://flowsta.com/sign-it/).

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Versioning Strategy](#versioning-strategy)
- [Security](#security)

## Code of Conduct

### Our Standards

- **Be respectful** — Treat all contributors with respect
- **Be constructive** — Provide helpful feedback
- **Be collaborative** — Work together toward common goals
- **Be inclusive** — Welcome diverse perspectives

### Unacceptable Behavior

- Harassment or discriminatory language
- Personal attacks or insults
- Publishing others' private information
- Other unprofessional conduct

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Rust 1.75+** — `rustup` for Rust toolchain management
- **Holochain 0.6.0** — Install via `nix-shell https://holochain.love`
- **Holochain CLI** — `cargo install holochain_cli`
- **Git** — For version control

### First-Time Setup

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/flowsta-signing-dna.git
cd flowsta-signing-dna

# 3. Add upstream remote
git remote add upstream https://github.com/WeAreFlowsta/flowsta-signing-dna.git

# 4. Build the latest version
cd v1.4
bash build.sh

# 5. Run tests
cargo test
```

## Development Setup

### Project Structure

```
flowsta-signing-dna/
├── v1.0/          # Historical — initial release
├── v1.1/          # Historical — added perceptual hashing
├── v1.2/          # Historical — web dashboard signing + cross-agent queries
├── v1.3/          # Historical — thumbnails + metadata extensions
├── v1.4/          # CURRENT VERSION — Work here!
│   ├── dna.yaml       # DNA configuration
│   ├── happ.yaml      # hApp bundle definition
│   ├── build.sh       # Build script
│   └── zomes/
│       └── signing/
│           ├── coordinator/
│           └── integrity/
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── SECURITY.md
```

### Building

```bash
cd v1.4

# Build DNA and hApp
bash build.sh

# Output: workdir/flowsta_signing_v1_4_happ.happ
```

### Testing Locally

```bash
# Run Rust unit tests
cd v1.4/zomes/signing/coordinator
cargo test

# Integration tests require a running conductor
hc sandbox create
hc sandbox run
```

## Making Changes

### Workflow

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** in the latest version directory (`v1.4/`)

3. **Test thoroughly** — both unit and integration tests

4. **Commit with clear messages**:
   ```bash
   git commit -m "feat: Add thumbnail validation"
   git commit -m "fix: Resolve revocation chain issue"
   git commit -m "docs: Update integration guide"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** on GitHub

### Commit Message Convention

We follow Conventional Commits:

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Test additions or updates
- `refactor:` — Code refactoring
- `perf:` — Performance improvements
- `chore:` — Maintenance tasks

Examples:
```
feat: Add perceptual hash band storage
fix: Resolve revocation agent key comparison
docs: Update content rights schema
test: Add unit tests for multi-signer links
```

## Testing

### Unit Tests

```bash
cd v1.4/zomes/signing/coordinator
cargo test
```

### Integration Tests

```bash
hc sandbox create
hc sandbox run
# Run integration tests against the running conductor
```

### Test Coverage

We aim for:
- **80%+ code coverage** for coordinator zomes
- **100% coverage** for critical functions (signature creation, revocation, content rights)
- **Edge cases** tested (max-length intent strings, malformed hashes, duplicate signatures, etc.)

## Pull Request Process

### Before Submitting

- ✅ Code builds successfully
- ✅ All tests pass
- ✅ Code follows Rust style guidelines (`rustfmt`)
- ✅ Documentation updated (if needed)
- ✅ No linter warnings (`cargo clippy`)

### PR Template

When opening a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No new warnings
```

### Review Process

1. **Automated checks** — CI runs tests and linters
2. **Code review** — Maintainers review your code
3. **Feedback** — Address any requested changes
4. **Approval** — Maintainers approve when ready
5. **Merge** — We merge into `main`

## Versioning Strategy

### When to Create a New Version

Create a new version (`v1.5/`, etc.) if:

- **Breaking changes** to entry types
- **Network seed change** required
- **Major new features** requiring migration

Coordinator-only changes (without touching integrity zomes) can be hot-swapped onto an existing DNA via `admin.updateCoordinators` without bumping the version — the DNA hash doesn't change.

### Creating a New Version

```bash
# Copy the latest version
cp -r v1.4 v1.5

# Update configuration
cd v1.5
# Edit dna.yaml: Update network_seed
# Edit happ.yaml: Update version info

# Make your changes in zomes/

# Document migration path if breaking
# Create v1.5/MIGRATION.md
```

### Version Compatibility

See [SECURITY.md](SECURITY.md#supported-versions) for the current supported-versions table.

## Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: security@flowsta.com

See [SECURITY.md](SECURITY.md) for detailed reporting guidelines.

### Security Considerations

When contributing to this DNA:

- ✅ **Never store PII** on the public DHT (email, display names, etc.)
- ✅ **Validate all inputs** before storing
- ✅ **Enforce signer-only actions** (revocation, thumbnail attachment)
- ✅ **Consider attack vectors** (forged signatures, DOS, spam, malicious data)
- ✅ **Test edge cases** (very large thumbnails, empty fields, duplicate signatures, etc.)

Remember: This is a **public DHT** — every signature and revocation is readable by anyone, forever.

## What We're Looking For

### High-Priority Contributions

- 🐛 **Bug fixes** — Especially in revocation / cross-agent query logic
- 🔐 **Security improvements** — Validation, DOS prevention
- 📚 **Documentation** — Integration guides, examples
- ✅ **Test coverage** — More comprehensive testing
- ⚡ **Performance** — Optimization of DHT operations

### Ideas for Contributions

- Improved perceptual hash robustness
- Better error messages and error handling
- Performance benchmarks and optimizations
- Integration examples for common frameworks
- Tutorials and guides for developers

## Questions?

- **General questions**: Open a GitHub Discussion
- **Bug reports**: Open a GitHub Issue
- **Feature requests**: Open a GitHub Issue
- **Security issues**: Email security@flowsta.com

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

---

Thank you for contributing to Flowsta! 🎉
