# Beginner Explanatory Guide: FINSERV-4215: Fix PII data masking pipeline

> **Task Type**: Service Task  
> **Domain/Focus**: Python fundamentals, Data Security

---

## 1. The Goal (In-Depth Beginner Explanation)

### The Core Problem
The task at hand addresses critical issues within a Personal Identifiable Information (PII) masking pipeline that is responsible for scanning database records and masking sensitive data such as Aadhaar numbers, PAN numbers, emails, and phone numbers before they are exported for analytics. Currently, there are two significant bugs in the system that allow unmasked PII to leak into exports, which poses a serious security risk. The first bug is related to the regular expression (regex) used for detecting Aadhaar numbers; it only matches a sequence of 12 consecutive digits and fails to account for common formats like "XXXX-XXXX-XXXX" or "XXXX XXXX XXXX". The second bug involves the logic of the masking process, where the masked values are computed but not returned, leading to the original unmasked record being exported instead.

Fixing these bugs is crucial not only for compliance with data protection regulations but also for maintaining user trust and safeguarding sensitive information. If these issues are not resolved, the application risks exposing sensitive data, which could lead to identity theft, legal repercussions, and damage to the organization's reputation.

### Jargon Buster (Key Terms Explained)
* **PII (Personally Identifiable Information)**: This refers to any data that could potentially identify a specific individual. Examples include names, social security numbers, and financial information. For instance, if a database contains a person's email address, that email address is considered PII because it can be used to identify or contact that person.

* **Regex (Regular Expression)**: A sequence of characters that forms a search pattern. It is used for string searching algorithms for "find" or "find and replace" operations on strings. For example, the regex `\b\d{12}\b` matches exactly 12 consecutive digits, but it would not match "1234-5678-9012" because of the hyphens.

* **Masking**: The process of obscuring specific data within a database to protect it from unauthorized access. For example, replacing a credit card number "1234-5678-9012-3456" with "****-****-****-3456" allows the last four digits to be visible while protecting the rest of the number.

* **Unit Tests**: These are automated tests written and run by software developers to ensure that a section of an application (usually a function or method) behaves as expected. For example, a unit test for the masking function would check if a given Aadhaar number is correctly masked.

### Expected Outcome
After implementing the solution, the PII masking pipeline should correctly identify and mask all specified PII types, including those in various formats. 

**Before Fix**: The pipeline may export records containing unmasked Aadhaar numbers in formats like "XXXX-XXXX-XXXX" and return the original unmasked records instead of the masked ones.

**After Fix**: The pipeline will successfully mask Aadhaar numbers in all formats and ensure that only the masked records are exported, thereby preventing any sensitive data from being leaked.

---

## 2. Related Coding Concepts & Syntax (50% Theory, 50% Practice)

### Concept 1: Regular Expressions (Regex)
#### 📘 Theoretical Overview (50%)
Regular expressions are powerful tools used in programming for pattern matching within strings. They allow developers to define complex search patterns that can match specific sequences of characters. Regex is particularly useful for validating formats, such as email addresses or phone numbers, and for searching through large texts for specific data.

If regex is not used, developers might resort to manual string manipulation, which can be error-prone and inefficient. Regex provides a concise and flexible way to perform these operations, making it easier to maintain and understand the code.

#### 💻 Syntax & Practical Examples (50%)
* **Language Syntax**:
  ```python
  import re
  
  # Example regex pattern to match a 12-digit Aadhaar number
  pattern = r'\b\d{12}\b'
  
  # Using re.search to find a match
  match = re.search(pattern, "My Aadhaar number is 123456789012.")
  if match:
      print("Match found:", match.group())
  ```

* **Real-World Application**:
  ```python
  import re
  
  # Function to mask Aadhaar numbers in a string
  def mask_aadhaar(text):
      pattern = r'\b\d{12}\b|\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
      return re.sub(pattern, '****-****-****', text)

  # Example usage
  original_text = "My Aadhaar number is 1234-5678-9012."
  masked_text = mask_aadhaar(original_text)
  print(masked_text)  # Output: My Aadhaar number is ****-****-****.
  ```

---

## 3. Step-by-Step Logic & Walkthrough

1. **Step 1: Locate and Analyze the Target File**
   * Navigate to the `dataMasker.py` file within the `s-w06-task-03` folder. This file contains the `DataMasker` class, which is responsible for masking PII.
   * Focus on the `mask_record` method, particularly the section where the masking logic is implemented. Look for the lines that handle the detection and masking of Aadhaar numbers.

2. **Step 2: Input Verification & Validation**
   * Before making changes, ensure that the input records are valid. Check for edge cases such as null or empty records. For example, if the input is `None`, the function should handle this gracefully without throwing an error.

3. **Step 3: Core Implementation / Modification**
   * Modify the regex pattern for Aadhaar detection to include formats with hyphens and spaces. Update the `PATTERNS` dictionary in the `PIIDetector` class:
     ```python
     'aadhaar': r'\b\d{12}\b|\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
     ```
   * Ensure that the masked values are returned instead of the original unmasked record. Update the `mask_record` method to return `masked_record` at the end of the function.

4. **Step 4: Output Verification & Testing**
   * After implementing the changes, run the unit tests defined in `test_dataMasker.py` to verify that all tests pass. This will confirm that the bugs have been fixed and that the masking functionality works as intended.

---

## 4. Detailed Walkthrough of Test Cases

### Test Case 1: Standard / Success Case
* **Description**: This test checks if the masking function correctly masks a valid Aadhaar number.
* **Inputs**:
  ```json
  {
      "aadhaar": "1234-5678-9012"
  }
  ```
* **Step-by-Step Execution Trace**:
  1. The input record is received by the `mask_record` function.
  2. The function detects the Aadhaar number using the updated regex pattern.
  3. The main logic runs, applying the mask to the detected Aadhaar number.
  4. Returns the masked record: `{"aadhaar": "****-****-****"}`.
* **Expected Output**: 
  ```json
  {
      "aadhaar": "****-****-****"
  }
  ```

### Test Case 2: Edge Case / Validation Fail
* **Description**: This test checks how the function handles an empty input.
* **Inputs**:
  ```json
  {}
  ```
* **Step-by-Step Execution Trace**:
  1. The empty input record is received by the `mask_record` function.
  2. The function checks if the record is empty and skips the masking logic.
  3. The execution is halted early, returning the original empty record.
* **Expected Output**: 
  ```json
  {}
  ```