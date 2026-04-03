# Contributing to NetMCP

Thank you for your interest in contributing to NetMCP! This document provides guidelines and instructions for contributing.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Setting Up the Development Environment

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/netmcp.git
   cd netmcp
   ```

2. **Create a virtual environment and install dependencies:**

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e ".[dev]"
   ```

3. **Verify the setup:**

   ```bash
   pytest
   ruff check .
   ```

### Prerequisites

Ensure you have the following installed on your system:

- **Python 3.11+**
- **tshark/Wireshark** (for packet capture and analysis)
- **Nmap** (for network scanning tools)

See [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=netmcp --cov-report=html

# Run a specific test file
pytest tests/test_capture.py

# Run tests matching a keyword
pytest -k "capture"
```

### Linting and Formatting

```bash
# Lint the codebase
ruff check .

# Auto-fix lint issues
ruff check --fix .

# Format code
ruff format .

# Type checking
mypy src/netmcp
```

### Pre-commit Checks

Before submitting a pull request, ensure:

- All tests pass: `pytest`
- Linting passes: `ruff check .`
- Type checking passes: `mypy src/netmcp`
- Code is formatted: `ruff format .`

## Pull Request Requirements

All pull requests must meet these criteria before they can be merged:

- **Tests required:** Every new feature or bugfix must include tests. PRs without tests will not be reviewed.
- **CI must pass:** All GitHub Actions checks must pass (linting, type checking, tests).
- **Coverage must not decrease:** New code should maintain or improve the current coverage level.
- **Documentation updated:** Update relevant documentation, docstrings, and the changelog.
- **Follows project conventions:** Code must follow the style and architecture conventions described below.

### PR Template

When opening a PR, include:

1. **Description** — What does this PR change and why?
2. **Related issues** — Link any related issues with `Closes #123` or `Fixes #123`.
3. **Testing** — Describe how you tested the changes.
4. **Breaking changes** — Note any breaking changes for users.

## Commit Message Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                                          |
|------------|------------------------------------------------------|
| `feat`     | A new feature                                        |
| `fix`      | A bug fix                                            |
| `docs`     | Documentation only changes                           |
| `style`    | Code style changes (formatting, semicolons, etc.)    |
| `refactor` | Code refactoring without behavior change             |
| `perf`     | Performance improvements                             |
| `test`     | Adding or fixing tests                               |
| `chore`    | Maintenance tasks, dependencies, config              |
| `ci`       | CI/CD pipeline changes                               |

### Examples

```
feat(tools): add nmap vulnerability scan tool
fix(analysis): handle malformed DNS responses gracefully
docs(readme): update installation instructions
test(capture): add tests for multi-interface capture
chore(deps): bump pytest-cov from 5.0.0 to 6.0.0
ci(github): add macOS runners to test matrix
```

### Scope

Use the tool or subsystem name as scope: `tools`, `analysis`, `capture`, `threat-intel`, `server`, `docs`, `ci`, `deps`.

## Branch Naming

Use descriptive branch names with the following conventions:

| Prefix        | Purpose                              | Example                                    |
|---------------|--------------------------------------|--------------------------------------------|
| `feature/*`   | New features                         | `feature/nmap-vuln-scan`                   |
| `fix/*`       | Bug fixes                            | `fix/dns-analysis-crash`                   |
| `docs/*`      | Documentation changes                | `docs/installation-guide`                  |
| `chore/*`     | Maintenance and configuration        | `chore/dependency-updates`                 |
| `refactor/*`  | Code refactoring                     | `refactor/extract-stream-parser`           |
| `test/*`      | Test additions or improvements       | `test/capture-tool-coverage`               |
| `ci/*`        | CI/CD changes                        | `ci/add-macos-runner`                      |

## How to Add New Tools

NetMCP tools follow a consistent structure. Here is how to add a new MCP tool:

### 1. Define the Tool

Add the tool definition in the appropriate module under `src/netmcp/tools/`. Use Pydantic models for input validation:

```python
from pydantic import BaseModel, Field

class MyToolInput(BaseModel):
    target: str = Field(description="Target host or IP address")
    option: str = Field(default="default", description="Tool option")
```

### 2. Implement the Tool Handler

Create the handler function that processes the input and returns an `mcp.types.TextContent` result:

```python
from netmcp.tools.my_tool import MyToolInput

async def handle_my_tool(input: MyToolInput) -> str:
    # Implementation here
    return f"Result for {input.target}"
```

### 3. Register the Tool

Add the tool to the server's tool registry in `src/netmcp/server.py`. Include the name, description, input schema, and handler.

### 4. Write Tests

Add tests in `tests/test_my_tool.py`:

```python
import pytest

@pytest.mark.asyncio
async def test_my_tool_success():
    result = await handle_my_tool(MyToolInput(target="127.0.0.1"))
    assert "expected output" in result

@pytest.mark.asyncio
async def test_my_tool_invalid_input():
    with pytest.raises(ValueError):
        await handle_my_tool(MyToolInput(target=""))
```

### 5. Update Documentation

- Add the tool to `README.md` in the tools table.
- Update `CHANGELOG.md` under the `[Unreleased]` section.
- Add a docstring to the handler function.

## Code Style

- **Line length:** 100 characters (enforced by Ruff).
- **Imports:** Sorted and grouped automatically (enforced by Ruff isort).
- **Type hints:** Use type hints for function signatures and variables.
- **Docstrings:** Every public function, class, and module must have a docstring.
- **Error handling:** Use specific exception types; never bare `except:`.
- **Async:** Use `async/await` for I/O operations.

## Release Process

Releases are managed by maintainers. The process:

1. Update `CHANGELOG.md` — move items from `[Unreleased]` to the new version.
2. Bump the version in `pyproject.toml`.
3. Tag the release: `git tag -a v0.2.0 -m "Release v0.2.0"`.
4. Push the tag: `git push origin v0.2.0`.
5. Publish to PyPI: `hatch build && hatch publish`.

## Questions?

- Open a [Discussion](https://github.com/luxvtz/netmcp/discussions) for general questions.
- Open an [Issue](https://github.com/luxvtz/netmcp/issues) for bugs or feature requests.
