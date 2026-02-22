# PR Review - PII data masking pipeline (by Sneha Jain)

## Reviewer: Pooja Reddy
---

**Overall:** Good foundation but critical bugs need fixing before merge.

### `dataMasker.py`

> **Bug #1:** Email masking reveals domain and masks user@gmail.com as ****@gmail.com instead of full mask
> This is the higher priority fix. Check the logic carefully and compare against the design doc.

### `maskingRules.py`

> **Bug #2:** Masking modifies the original object instead of creating a copy and source data is corrupted
> This is more subtle but will cause issues in production. Make sure to add a test case for this.

---

**Sneha Jain**
> Acknowledged. I have documented the issues for whoever picks this up.
