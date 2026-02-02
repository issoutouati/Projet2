# Strict Automatic Exam Correction System

A deterministic, rule-based automatic exam correction system that strictly follows a provided correction model without interpretation, inference, or flexibility.

## Core Principles

1. **Zero Tolerance**: No interpretation, guessing, or inference allowed
2. **Correction Model Only**: Uses only the explicitly provided correction model
3. **Exact Matching**: Answers must match exactly according to defined rules
4. **No External Knowledge**: The system does not use its own knowledge
5. **Deterministic Scoring**: Same inputs always produce same outputs

## Features

- **Multi-Format Input Support**:
  - Typed text
  - Images (with OCR)
  - PDF documents
  
- **Strict Matching Rules**:
  - Exact text matching (case-sensitive by default)
  - No synonyms unless explicitly defined
  - No partial credit unless specified in correction model
  - Per-question scoring (not global zero)
  
- **Detailed PDF Reports**:
  - Student answers displayed
  - Errors clearly marked
  - Per-question scores
  - Final grade out of 20
  - Explanation for each error

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### CLI Mode

```bash
# Text-based correction
python -m exam_corrector correct \
  --correction-model correction_model.json \
  --student-exam student_answers.json \
  --output report.pdf

# Image-based correction
python -m exam_corrector correct \
  --correction-model correction_model.jpg \
  --student-exam student_exam.jpg \
  --output report.pdf \
  --use-ocr
```

### Python API

```python
from exam_corrector import ExamCorrector

corrector = ExamCorrector()

# Load correction model
corrector.load_correction_model("correction_model.json")

# Load student exam
corrector.load_student_exam("student_answers.json")

# Perform strict correction
result = corrector.correct()

# Generate PDF report
corrector.generate_report(result, "report.pdf")
```

## Correction Model Format

```json
{
  "exam_title": "Mathematics Final Exam",
  "total_points": 100,
  "matching_rules": {
    "case_sensitive": true,
    "ignore_whitespace": true,
    "allow_synonyms": false
  },
  "questions": [
    {
      "question_id": 1,
      "question_text": "What is 2+2?",
      "correct_answer": "4",
      "points": 10,
      "matching_type": "exact"
    },
    {
      "question_id": 2,
      "question_text": "What is the capital of France?",
      "correct_answer": "Paris",
      "points": 10,
      "matching_type": "exact"
    }
  ]
}
```

## System Behavior

- **Deterministic**: Always produces the same result for the same inputs
- **Strict**: In case of ambiguity, assigns 0 points
- **Rule-Based**: No AI interpretation or flexibility
- **Per-Question Scoring**: Each question scored independently

## License

MIT License
