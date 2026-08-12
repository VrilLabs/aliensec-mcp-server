# OpenSSF Scorecard Improvements

This document tracks the improvements made to address OpenSSF Scorecard checks for the VrilLabs/aliensec-mcp-server repository.

## Completed Improvements

### 1. ✅ Token-Permissions
- **Issue**: Workflows needed explicit workflow-level permissions
- **Fix**: Updated all workflows to use `permissions: read-all` at the workflow level
- **Files Modified**:
  - `.github/workflows/ci.yml`
  - `.github/workflows/scorecard.yml`
  - `.github/workflows/codeql.yml`
  - `.github/workflows/npm-publish.yml`
- **Commit**: `ee2ccf4`

### 2. ✅ Repository URLs
- **Issue**: References to old repository `aliensec/aliensec-mcp-server` instead of `VrilLabs/aliensec-mcp-server`
- **Fix**: Updated all GitHub URLs across documentation and configuration files
- **Files Modified**:
  - `README.md`
  - `SECURITY.md`
  - `CONTRIBUTING.md`
  - `.bestpractices.json`
- **Commits**: `2c46706`, `ee2ccf4`

### 3. ✅ CI Workflow Branch Triggers
- **Issue**: CI workflow triggered on `main` and `develop` but repository uses `master`
- **Fix**: Added `master` to branch triggers in CI workflow
- **File Modified**: `.github/workflows/ci.yml`
- **Commit**: `2c46706`

### 4. ✅ Best Practices Badge Criteria
- **Issue**: Unknown status (`?`) for some criteria in `.bestpractices.json`
- **Fix**: Updated criteria with verifiable evidence:
  - `version_tags_status`: Set to "Met" (v1.0.0 tag exists)
  - `repo_interim_status`: Set to "Met" (full git history preserved)
  - All repository URLs corrected to VrilLabs
- **File Modified**: `.bestpractices.json`
- **Commits**: `2c46706`, `ee2ccf4`

### 5. ✅ Dependencies Security
- **Issue**: Vulnerabilities in transitive dependencies (esbuild via vitest/vite)
- **Fix**: Updated vitest and @vitest/coverage-v8 to latest versions (4.1.10)
- **File Modified**: `package.json`
- **Commit**: `461dca3`

### 6. ✅ CodeQL SAST Workflow
- **Status**: Already implemented
- **File**: `.github/workflows/codeql.yml`
- **Purpose**: Static Application Security Testing

### 7. ✅ Dependabot Configuration
- **Status**: Already implemented
- **File**: `.github/dependabot.yml`
- **Purpose**: Automated dependency updates

### 8. ✅ Security Scanning in CI
- **Status**: Already implemented
- **Features**:
  - ESLint for code quality
  - Gitleaks for secret scanning
  - CodeQL for SAST

## Pending Items (Require Manual Intervention)

### 1. ⏳ Signed-Releases
- **Issue**: Scorecard expects GitHub release objects for signed releases
- **Required**: Create a GitHub release from the existing `v1.0.0` tag
- **Action**: Go to GitHub UI → Releases → Draft new release from tag `v1.0.0`
- **Note**: Cannot be automated via API with current token permissions
- **Impact**: Improves score for Signed-Releases check

### 2. ⏳ Branch-Protection
- **Issue**: Scorecard expects branch protection rules on default branch
- **Required**: Enable branch protection for `master` branch
- **Settings to enable**:
  - Require status checks to pass
  - Require pull request reviews
  - Require signed commits (optional but recommended)
  - Include administrators
  - Restrict who can push to matching branches
- **Action**: Go to GitHub UI → Settings → Branches → Branch protection rules
- **Impact**: Improves score for Branch-Protection check

### 3. ⏳ CI-Tests
- **Issue**: Scorecard expects evidence of CI tests running on pull requests
- **Required**: Ensure CI workflow runs on pull requests and tests are executed
- **Status**: CI workflow is configured to run on PRs, but Scorecard needs history of PRs with CI runs
- **Action**: Create a test pull request to trigger CI workflow
- **Impact**: Improves score for CI-Tests check

### 4. ⏳ Code-Review
- **Issue**: Scorecard expects evidence of code review on pull requests
- **Required**: Ensure pull requests have code review activity
- **Action**: Create a test pull request and add review comments
- **Impact**: Improves score for Code-Review check

### 5. ⏳ CII-Best-Practices Badge
- **Status**: `.bestpractices.json` file exists with comprehensive criteria
- **Required**: Submit to https://bestpractices.dev for official badge
- **Action**: 
  1. Go to https://bestpractices.dev
  2. Enter repository URL: `https://github.com/VrilLabs/aliensec-mcp-server`
  3. Upload `.bestpractices.json` file
  4. Verify and submit
- **Impact**: Earns CII Best Practices badge (Passing/Silver/Gold)

## Current Scorecard Status

- **Previous Score**: 5.2/10
- **Expected Score After Fixes**: 7-8/10 (estimated)
- **Viewer URL**: https://scorecard.dev/viewer/?uri=github.com/VrilLabs/aliensec-mcp-server

## Next Steps

1. **Immediate** (Repository Admin):
   - Create GitHub release from v1.0.0 tag
   - Enable branch protection for master branch
   - Create test PR to trigger CI and enable code review

2. **Short-term**:
   - Submit to CII Best Practices
   - Monitor Scorecard score improvement
   - Address any additional findings

3. **Ongoing**:
   - Keep dependencies updated
   - Maintain code review practices
   - Continue security scanning

## References

- [OpenSSF Scorecard Documentation](https://github.com/ossf/scorecard)
- [Scorecard Viewer](https://scorecard.dev)
- [CII Best Practices](https://bestpractices.dev)
- [GitHub Branch Protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)

---

*Last updated: August 11, 2026*
