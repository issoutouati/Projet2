# Usage Guide - Strict Automatic Exam Correction System

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Core Principles](#core-principles)
4. [Command Line Interface](#command-line-interface)
5. [Python API](#python-api)
6. [Correction Model Format](#correction-model-format)
7. [Student Exam Format](#student-exam-format)
8. [Matching Types](#matching-types)
9. [Examples](#examples)

## Overview

This system is a **deterministic, rule-based** exam correction tool that:
- Strictly follows the correction model provided
- Never interprets, guesses, or infers answers
- Assigns 0 points for non-matching answers (per question, not globally)
- Scores each question independently
- Generates detailed PDF reports

## Installation

```bash
# Clone or download the repository
cd exam-corrector

# Install dependencies
pip install -r requirements.txt

# Or install the package
pip install -e .
```

## Core Principles

### NON-NEGOTIABLE Rules

1. **No Interpretation**: The system does not understand meaning
2. **Exact Matching**: Only matches according to defined rules
3. **No Synonyms**: Unless explicitly defined in correction model
4. **No External Knowledge**: Only uses the correction model
5. **No Partial Credit**: Unless explicitly defined per question
6. **Per-Question Scoring**: Wrong answer = 0 for that question only

### Strictness Example

```json
Question: "What is 2+2?"
Correct Answer (in model): "4"

Student answers:
- "4" → ✓ Correct (10/10 points)
- "four" → ✗ Incorrect (0/10 points) - No interpretation
- "4.0" → ✗ Incorrect (0/10 points) - Not exact match
- " 4 " → ✓ Correct (if ignore_whitespace=true)
```

## Command Line Interface

### Basic Correction

```bash
python -m exam_corrector correct \
  --correction-model examples/correction_model_example.json \
  --student-exam examples/student_exam_partial.json \
  --output report.pdf
```

### With OCR (for images/PDFs)

```bash
python -m exam_corrector correct \
  --correction-model correction_model.jpg \
  --student-exam student_exam.pdf \
  --output report.pdf \
  --use-ocr
```

### Verbose Output

```bash
python -m exam_corrector correct \
  --correction-model model.json \
  --student-exam exam.json \
  --output report.pdf \
  --verbose
```

### Create Template

```bash
python -m exam_corrector create-template my_template.json
```

## Python API

### Basic Usage

```python
from exam_corrector import ExamCorrector
from exam_corrector.parser import InputParser
from exam_corrector.report_generator import ReportGenerator

# Initialize
parser = InputParser()
corrector = ExamCorrector()
report_gen = ReportGenerator()

# Load correction model
model = parser.parse_correction_model("correction_model.json")
corrector.load_correction_model(model)

# Load student exam
exam = parser.parse_student_exam("student_exam.json")
corrector.load_student_exam(exam)

# Perform correction
result = corrector.correct()

# Generate report
report_gen.generate_report(result, "output_report.pdf")

# Access results
print(f"Final Grade: {result.final_grade_out_of_20}/20")
print(f"Total Points: {result.total_points_awarded}/{result.total_possible_points}")
```

### Using Dictionaries

```python
from exam_corrector import ExamCorrector
from exam_corrector.models import CorrectionModel, StudentExam, Question, StudentAnswer

# Create correction model
model = CorrectionModel(
    exam_title="Quick Test",
    total_points=20,
    questions=[
        Question(
            question_id=1,
            question_text="What is 2+2?",
            correct_answer="4",
            points=10,
            matching_type="exact"
        ),
        Question(
            question_id=2,
            question_text="What is 3+3?",
            correct_answer="6",
            points=10,
            matching_type="exact"
        )
    ]
)

# Create student exam
exam = StudentExam(
    student_name="John Doe",
    student_id="12345",
    answers=[
        StudentAnswer(question_id=1, answer="4"),
        StudentAnswer(question_id=2, answer="6")
    ]
)

# Correct
corrector = ExamCorrector()
corrector.load_correction_model(model)
corrector.load_student_exam(exam)
result = corrector.correct()
```

## Correction Model Format

### Structure

```json
{
  "exam_title": "Exam Title",
  "total_points": 100,
  "matching_rules": {
    "case_sensitive": true,
    "ignore_whitespace": true,
    "allow_synonyms": false
  },
  "questions": [
    {
      "question_id": 1,
      "question_text": "Question text here",
      "correct_answer": "Expected answer",
      "points": 10,
      "matching_type": "exact",
      "case_sensitive": true,
      "ignore_whitespace": true
    }
  ]
}
```

### Fields Explanation

- `exam_title`: Title of the exam
- `total_points`: Total possible points (must equal sum of question points)
- `matching_rules`: Global matching rules
  - `case_sensitive`: If false, "Paris" = "paris"
  - `ignore_whitespace`: If true, "Hello  World" = "Hello World"
  - `allow_synonyms`: Must be false (synonyms not supported)
- `questions`: Array of question objects
  - `question_id`: Unique identifier
  - `question_text`: The question
  - `correct_answer`: Exact expected answer
  - `points`: Points for this question
  - `matching_type`: "exact", "contains", or "regex"
  - `case_sensitive`: Override global setting (optional)
  - `ignore_whitespace`: Override global setting (optional)

## Student Exam Format

```json
{
  "student_name": "John Doe",
  "student_id": "12345",
  "answers": [
    {
      "question_id": 1,
      "answer": "Student's answer"
    },
    {
      "question_id": 2,
      "answer": "Another answer"
    }
  ]
}
```

## Matching Types

### 1. Exact Match (`"matching_type": "exact"`)

The student answer must match the correct answer exactly (after applying case/whitespace rules).

```json
{
  "correct_answer": "Paris",
  "matching_type": "exact"
}
```

- "Paris" → ✓
- "paris" → ✗ (if case_sensitive=true)
- "The answer is Paris" → ✗

### 2. Contains Match (`"matching_type": "contains"`)

The student answer must contain the correct answer.

```json
{
  "correct_answer": "Paris",
  "matching_type": "contains"
}
```

- "Paris" → ✓
- "The capital is Paris" → ✓
- "Paris is beautiful" → ✓
- "London" → ✗

### 3. Regex Match (`"matching_type": "regex"`)

The student answer must match the regex pattern.

```json
{
  "correct_answer": "\\d+",
  "matching_type": "regex"
}
```

- "123" → ✓
- "42" → ✓
- "abc" → ✗

**Note**: Invalid regex always results in 0 points (strictest interpretation).

## Examples

### Example 1: Perfect Score

Correction Model:
```json
{
  "exam_title": "Math Quiz",
  "total_points": 20,
  "questions": [
    {
      "question_id": 1,
      "question_text": "2+2=?",
      "correct_answer": "4",
      "points": 10
    },
    {
      "question_id": 2,
      "question_text": "3+3=?",
      "correct_answer": "6",
      "points": 10
    }
  ]
}
```

Student Exam:
```json
{
  "student_name": "Alice",
  "answers": [
    {"question_id": 1, "answer": "4"},
    {"question_id": 2, "answer": "6"}
  ]
}
```

Result:
- Question 1: 10/10 ✓
- Question 2: 10/10 ✓
- Total: 20/20
- Final Grade: 20/20

### Example 2: No Interpretation

Correction Model:
```json
{
  "exam_title": "Math Quiz",
  "total_points": 10,
  "questions": [
    {
      "question_id": 1,
      "question_text": "2+2=?",
      "correct_answer": "4",
      "points": 10
    }
  ]
}
```

Student Exam:
```json
{
  "student_name": "Bob",
  "answers": [
    {"question_id": 1, "answer": "four"}
  ]
}
```

Result:
- Question 1: 0/10 ✗ (Answer does not match correction model)
- Total: 0/10
- Final Grade: 0/20

**Why?** The system does not interpret "four" as "4". It only uses exact matching as defined in the correction model.

### Example 3: Per-Question Scoring

Correction Model:
```json
{
  "exam_title": "Quiz",
  "total_points": 30,
  "questions": [
    {"question_id": 1, "correct_answer": "A", "points": 10},
    {"question_id": 2, "correct_answer": "B", "points": 10},
    {"question_id": 3, "correct_answer": "C", "points": 10}
  ]
}
```

Student Exam:
```json
{
  "answers": [
    {"question_id": 1, "answer": "A"},
    {"question_id": 2, "answer": "Wrong"},
    {"question_id": 3, "answer": "C"}
  ]
}
```

Result:
- Question 1: 10/10 ✓
- Question 2: 0/10 ✗
- Question 3: 10/10 ✓
- Total: 20/30
- Final Grade: 13.33/20

**Important**: Question 2 is wrong, but it doesn't cause a global zero. Each question is scored independently.

### Example 4: Case Sensitivity

Correction Model:
```json
{
  "matching_rules": {
    "case_sensitive": false
  },
  "questions": [
    {
      "question_id": 1,
      "correct_answer": "Paris",
      "points": 10
    }
  ]
}
```

Student Exam:
```json
{
  "answers": [
    {"question_id": 1, "answer": "PARIS"}
  ]
}
```

Result: ✓ Correct (case_sensitive=false)

### Example 5: OCR Processing

```bash
# Student submitted a scanned paper exam
python -m exam_corrector correct \
  --correction-model model.json \
  --student-exam scanned_exam.pdf \
  --output report.pdf \
  --use-ocr
```

The system will:
1. Extract text from the PDF using OCR
2. Parse the extracted text as JSON
3. Apply strict matching rules
4. Generate PDF report

## Output Report

The generated PDF report includes:

1. **Header**
   - Exam title
   - Student name and ID

2. **Summary**
   - Total points awarded
   - Percentage score
   - Final grade out of 20

3. **Detailed Results**
   - For each question:
     - Question text
     - Student's answer
     - Correct answer
     - Status (✓ or ✗)
     - Explanation
     - Points awarded

4. **Color Coding**
   - Green ✓: Correct answers
   - Red ✗: Incorrect answers

## Troubleshooting

### "Answer does not match the correction model"

This means the student's answer does not exactly match the expected answer. Check:
- Case sensitivity settings
- Whitespace handling
- Exact text match

### All questions are marked wrong

Verify:
- Question IDs match between correction model and student exam
- Matching rules are correctly configured
- Correct answers are exactly as expected

### OCR not working

Ensure:
- Tesseract OCR is installed on your system
- Image/PDF quality is good
- Text is clearly legible

## Best Practices

1. **Test Your Correction Model**: Run it with sample exams first
2. **Be Explicit**: Define exact expected answers
3. **Document Rules**: Share matching rules with students
4. **Use Case Insensitivity Carefully**: Only when truly needed
5. **Validate Total Points**: Ensure sum of question points equals total_points
6. **Keep It Simple**: Prefer exact matching over regex when possible

## Support

For issues or questions, please refer to the README.md or open an issue in the repository.
