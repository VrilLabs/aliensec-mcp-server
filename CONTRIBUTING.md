# Contributing to AlienSec MCP Server

Thank you for your interest in contributing to the AlienSec MCP Server! We welcome contributions from everyone.

## How to Contribute

### Reporting Bugs

If you find a bug, please:

1. Check the [existing issues](https://github.com/aliensec/aliensec-mcp-server/issues) to see if it's already been reported
2. Open a new issue with:
   - A clear, descriptive title
   - Steps to reproduce the issue
   - Expected and actual behavior
   - Environment details (Node.js version, OS, etc.)
   - Relevant log output or error messages

### Suggesting Features

Feature requests are welcome! Please:

1. Check the [existing issues](https://github.com/aliensec/aliensec-mcp-server/issues) for similar requests
2. Open a new issue with:
   - A clear description of the feature
   - The use case or problem it would solve
   - Any relevant examples or references

### Code Contributions

#### Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/aliensec-mcp-server.git
   cd aliensec-mcp-server
   ```
3. Install dependencies:
   ```bash
   npm install
   ```
4. Create a feature branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```

#### Development Workflow

- Run tests to ensure everything is working:
  ```bash
  npm test
  ```

- Run linting:
  ```bash
  npm run lint
  ```

- Format your code:
  ```bash
  npm run format
  ```

- Type check your changes:
  ```bash
  npm run typecheck
  ```

#### Submitting a Pull Request

1. Push your changes to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
2. Open a Pull Request on the main repository
3. Ensure all CI checks pass
4. Address any review comments

### Pull Request Guidelines

- Use [Conventional Commits](https://www.conventionalcommits.org/) format for commit messages
- Keep commits atomic and focused on a single logical change
- Provide a clear description of the changes in the PR
- Reference any relevant issues
- Ensure all tests pass and linting is clean

### Code Style

- Follow the existing code patterns and conventions
- Use TypeScript types consistently
- Keep functions small and focused
- Add appropriate comments for complex logic
- Use meaningful variable and function names

## Testing

All contributions should include appropriate tests. Run the full test suite with:

```bash
npm test
```

For watch mode:

```bash
npm run test:watch
```

For coverage reports:

```bash
npx vitest run --coverage
```

## Security Issues

**Do not report security vulnerabilities through public GitHub issues.**

Please refer to our [Security Policy](SECURITY.md) for instructions on reporting security vulnerabilities.

## License

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Code of Conduct

This project follows a Code of Conduct to ensure a welcoming and inclusive community. Please be respectful and considerate of others when contributing.

---

Thank you for contributing to AlienSec MCP Server!
