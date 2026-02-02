# Quick Start Guide

Get started with the Strict Automatic Exam Correction System in 5 minutes.

## Installation

```bash
# Clone/download the repository
cd exam-corrector

# Install dependencies
pip install -r requirements.txt

# Or install the package
pip install -e .
```

## Basic Usage - 3 Steps

### Step 1: Create a Correction Model

Create a JSON file defining your exam and correct answers:

```bash
python -m exam_corrector create-template my_exam.json
```

Or create manually (`correction_model.json`):

```json
{
  "exam_title": "My First Exam",
  "total_points": 20,
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
      "question_text": "What is 3+3?",
      "correct_answer": "6",
      "points": 10,
      "matching_type": "exact"
    }
  ]
}
```

### Step 2: Create Student Exam

Create a JSON file with student's answers (`student_exam.json`):

```json
{
  "student_name": "John Doe",
  "student_id": "12345",
  "answers": [
    {
      "question_id": 1,
      "answer": "4"
    },
    {
      "question_id": 2,
      "answer": "6"
    }
  ]
}
```

### Step 3: Run Correction

```bash
python -m exam_corrector correct \
  --correction-model correction_model.json \
  --student-exam student_exam.json \
  --output report.pdf \
  --verbose
```

Done! Check `report.pdf` for the detailed results.

## Example Run

Try the included examples:

```bash
# Perfect score example
python -m exam_corrector correct \
  --correction-model examples/correction_model_example.json \
  --student-exam examples/student_exam_perfect.json \
  --output report_perfect.pdf \
  --verbose

# Partial score example
python -m exam_corrector correct \
  --correction-model examples/correction_model_example.json \
  --student-exam examples/student_exam_partial.json \
  --output report_partial.pdf \
  --verbose
```

## Python API

```python
from exam_corrector import ExamCorrector
from exam_corrector.parser import InputParser
from exam_corrector.report_generator import ReportGenerator

# Initialize
parser = InputParser()
corrector = ExamCorrector()
report_gen = ReportGenerator()

# Load files
model = parser.parse_correction_model("correction_model.json")
exam = parser.parse_student_exam("student_exam.json")

# Correct
corrector.load_correction_model(model)
corrector.load_student_exam(exam)
result = corrector.correct()

# Generate report
report_gen.generate_report(result, "report.pdf")

print(f"Final Grade: {result.final_grade_out_of_20}/20")
```

## Run the Demo

```bash
python demo.py
```

This will demonstrate:
- Strict correction (no interpretation)
- Per-question scoring
- Case sensitivity options
- Different matching types
- PDF report generation

## Important Rules

**The system will:**
- ✓ Match answers exactly as defined in the correction model
- ✓ Score each question independently
- ✓ Assign 0 points for non-matching answers (per question)
- ✓ Generate detailed PDF reports

**The system will NOT:**
- ✗ Interpret or guess meanings ("four" ≠ "4")
- ✗ Accept synonyms unless explicitly defined ("big" ≠ "large")
- ✗ Use its own knowledge
- ✗ Give partial credit unless specified
- ✗ Assign global zero (wrong answer = 0 for that question only)

## Need Help?

- See [USAGE.md](USAGE.md) for detailed documentation
- Run `python -m exam_corrector --help` for CLI options
- Check the `examples/` directory for sample files
- Run `python demo.py` to see the system in action

## Next Steps

1. Create your own correction model
2. Collect student exams in JSON format (or use OCR for images/PDFs)
3. Run the correction system
4. Review the generated PDF reports

For OCR support (images/PDFs):

```bash
# Install OCR dependencies (requires Tesseract OCR)
pip install pytesseract pdf2image

# Run with OCR
python -m exam_corrector correct \
  --correction-model model.jpg \
  --student-exam exam.pdf \
  --output report.pdf \
  --use-ocr
```
