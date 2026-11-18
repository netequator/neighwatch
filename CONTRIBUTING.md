# Contributing to neighwatch

Thank you for contributing to `neighwatch`. This project adheres to disciplined engineering, reproducible packet dissection, and minimal runtime dependencies.

---

## 1. Development Environment

### Prerequisites
- Python 3.10 or newer (tested on 3.12).
- Virtual environment (`venv`) to isolate dependencies.
- `ruff` for linting and code formatting.
- `pytest` for deterministic unit testing.

### Setup
```bash
git clone https://github.com/netequator/neighwatch.git
cd neighwatch
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install pytest ruff build
pip install -e .
```

---

## 2. Engineering Standards

### Zero "AI Smell" & Minimalist Code
- Do not include emojis anywhere: commit messages, PR descriptions, code comments, documentation, or CLI outputs.
- Keep abstractions narrow. Do not introduce generic factories, speculative interfaces, or heavy third-party dependencies.
- Use Python standard library primitives wherever possible (e.g., `struct`, `socket`, `dataclasses`).

### Deterministic Testing
- Live capture code must remain cleanly separated from binary parsing logic.
- All new protocol features or bug fixes must include deterministic unit tests in `tests/` using synthetic byte buffers or offline `.pcap` / `.pcapng` streams.
- Tests must execute without requiring root/administrator permissions or active network interfaces.

### Code Quality Checklist
Before submitting a pull request, verify:
```bash
ruff check .
pytest tests/ -v
```

---

## 3. Git & Pull Request Guidelines

### Commit Messages
- Use concise, lower-case technical descriptions explaining the specific change.
- Format: `<type>: <description>`
  - `feat: add ipv6 rfc4861 tlla parsing`
  - `fix: correct pcapng 32-bit alignment padding`
  - `test: add deterministic test for arp probe quarantine`
  - `refactor: simplify sliding window counter eviction`
  - `docs: update systemd ambient capabilities section`

### Scope Discipline
- Keep pull requests focused on a single GitHub Issue or feature.
- Avoid multi-issue mega-commits. Group changes into 1 to 3 logical commits.
- Ensure all CI tests pass and the repository tree remains clean.
