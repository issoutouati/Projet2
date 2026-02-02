# Documentation Index

Complete guide to all documentation files in this project.

## Quick Start (Read This First!)
- Installation instructions
- Basic usage (3 simple steps)
- Example runs
- Quick reference

## Understanding The System
- What this system is
- Core features
- Installation
- Basic examples

- What "strict" means in practice
- Examples of strictness
- When ambiguity occurs
- Common pitfalls
- Best practices

## Complete Reference
- Command-line interface (CLI) reference
- Python API reference
- Correction model format
- Student exam format
- Matching types explained
- Detailed examples
- Troubleshooting

- All implemented features
- Configuration options
- Use cases (ideal/not ideal)
- System guarantees
- Technical specifications

## Project Information
- Project structure
- Technical stack
- Test results
- Example scenarios
- Who should use this

## Interactive Learning
- Run: `python demo.py`
- Shows all features in action
- Generates example reports
- Educational code examples

## Examples
- `correction_model_example.json` - Sample exam definition
- `student_exam_perfect.json` - Perfect score example
- `student_exam_partial.json` - Partial score example

## Reading Order Recommendations

### For First-Time Users:
1. README.md (5 min)
2. QUICKSTART.md (5 min)
3. Run `python demo.py` (5 min)
4. Try examples with CLI (10 min)

### For Developers:
1. README.md (5 min)
2. PROJECT_SUMMARY.md (10 min)
3. FEATURES.md (10 min)
4. Review code in `exam_corrector/` (30 min)
5. Check tests in `tests/` (15 min)

### For Understanding Behavior:
1. STRICTNESS_GUIDE.md (15 min)
2. Run `python demo.py` (5 min)
3. Read test cases in `tests/` (20 min)

### For Production Use:
1. QUICKSTART.md (5 min)
2. USAGE.md (20 min)
3. STRICTNESS_GUIDE.md (15 min)
4. Test with your own data (30 min)

## Help & Support

- **CLI Help**: `python -m exam_corrector --help`
- **Command Help**: `python -m exam_corrector correct --help`
- **Version**: `python -m exam_corrector --version`
- **Tests**: `python -m pytest tests/ -v`
- **Demo**: `python demo.py`

## File Sizes & Reading Times

| File | Size | Est. Reading Time |
|------|------|------------------|
| README.md | 2.8 KB | 5 minutes |
| QUICKSTART.md | 4.1 KB | 5 minutes |
| STRICTNESS_GUIDE.md | 8.4 KB | 15 minutes |
| USAGE.md | 10.8 KB | 20 minutes |
| FEATURES.md | 8.6 KB | 15 minutes |
| PROJECT_SUMMARY.md | 8.0 KB | 15 minutes |
| demo.py | 10.7 KB | 5-10 minutes to run |

**Total Reading Time**: ~75 minutes to read everything

## Quick Reference Cards

### Essential Commands
```bash
# Install
pip install -r requirements.txt

# Correct an exam
python -m exam_corrector correct -c model.json -s exam.json -o report.pdf

# Create template
python -m exam_corrector create-template template.json

# Run demo
python demo.py

# Run tests
python -m pytest tests/
```

### Essential Code
```python
from exam_corrector import ExamCorrector
from exam_corrector.parser import InputParser
from exam_corrector.report_generator import ReportGenerator

parser = InputParser()
corrector = ExamCorrector()
report_gen = ReportGenerator()

model = parser.parse_correction_model("model.json")
exam = parser.parse_student_exam("exam.json")

corrector.load_correction_model(model)
corrector.load_student_exam(exam)
result = corrector.correct()

report_gen.generate_report(result, "report.pdf")
```

## Documentation Quality

- ✅ All files use markdown format
- ✅ Clear headings and structure
- ✅ Code examples included
- ✅ Tables for comparisons
- ✅ Real-world examples
- ✅ Troubleshooting sections
- ✅ Cross-references between docs

## Updates & Maintenance

This documentation is kept in sync with the code. When features change:
1. Code is updated first
2. Tests are updated
3. Documentation is updated
4. Examples are updated

Version: 1.0.0
Last Updated: 2024
