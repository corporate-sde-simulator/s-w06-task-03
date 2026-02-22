# FINSERV-4215: Fix PII data masking pipeline

**Status:** In Progress · **Priority:** Critical
**Sprint:** Sprint 28 · **Story Points:** 5
**Reporter:** Anjali Nair (Security Lead) · **Assignee:** You (Intern)
**Due:** End of sprint (Friday)
**Labels:** `backend`, `python`, `security`, `pii`
**Task Type:** Bug Fix

---

## Description

The PII masking pipeline scans database records and masks sensitive data (Aadhaar, PAN, email, phone) before exporting to analytics. Two bugs are causing unmasked PII to leak into exports. Bugs are marked with `# BUG:` comments.

## Acceptance Criteria

- [ ] Bug #1 fixed: Regex for Aadhaar detection misses the common XXXX-XXXX-XXXX format (only matches 12 consecutive digits)
- [ ] Bug #2 fixed: Masked values are stored in a local variable but the original unmasked record is returned
- [ ] All unit tests pass
