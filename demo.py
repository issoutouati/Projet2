"""
Demo script showing how to use the Strict Automatic Exam Correction System.
This demonstrates the core principles and features of the system.
"""

from exam_corrector import ExamCorrector
from exam_corrector.models import (
    CorrectionModel,
    StudentExam,
    Question,
    StudentAnswer,
    MatchingRules
)
from exam_corrector.report_generator import ReportGenerator


def demo_strict_correction():
    """Demonstrate strict correction with no interpretation."""
    print("=" * 80)
    print("DEMO: Strict Correction - NO INTERPRETATION")
    print("=" * 80)
    
    model = CorrectionModel(
        exam_title="Strict Correction Demo",
        total_points=30,
        matching_rules=MatchingRules(
            case_sensitive=True,
            ignore_whitespace=True,
            allow_synonyms=False
        ),
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
                question_text="What is the result of 10/2?",
                correct_answer="5",
                points=10,
                matching_type="exact"
            ),
            Question(
                question_id=3,
                question_text="What is a large number?",
                correct_answer="big",
                points=10,
                matching_type="exact"
            )
        ]
    )
    
    exam = StudentExam(
        student_name="Demo Student",
        student_id="DEMO001",
        answers=[
            StudentAnswer(question_id=1, answer="4"),
            StudentAnswer(question_id=2, answer="five"),
            StudentAnswer(question_id=3, answer="large")
        ]
    )
    
    corrector = ExamCorrector()
    corrector.load_correction_model(model)
    corrector.load_student_exam(exam)
    result = corrector.correct()
    
    print("\nResults:")
    for qr in result.question_results:
        status = "✓ CORRECT" if qr.is_correct else "✗ INCORRECT"
        print(f"\nQuestion {qr.question_id}: {qr.question_text}")
        print(f"  Student Answer: '{qr.student_answer}'")
        print(f"  Correct Answer: '{qr.correct_answer}'")
        print(f"  {status}")
        print(f"  Explanation: {qr.explanation}")
        print(f"  Score: {qr.points_awarded}/{qr.max_points}")
    
    print(f"\nFinal Grade: {result.final_grade_out_of_20}/20")
    print("\nKey Observations:")
    print("  - Question 1: '4' matches '4' → Correct")
    print("  - Question 2: 'five' does NOT match '5' → Incorrect (no interpretation)")
    print("  - Question 3: 'large' does NOT match 'big' → Incorrect (no synonyms)")


def demo_per_question_scoring():
    """Demonstrate per-question scoring (not global zero)."""
    print("\n" + "=" * 80)
    print("DEMO: Per-Question Scoring - NO GLOBAL ZERO")
    print("=" * 80)
    
    model = CorrectionModel(
        exam_title="Per-Question Scoring Demo",
        total_points=40,
        questions=[
            Question(question_id=1, question_text="Q1", correct_answer="A", points=10),
            Question(question_id=2, question_text="Q2", correct_answer="B", points=10),
            Question(question_id=3, question_text="Q3", correct_answer="C", points=10),
            Question(question_id=4, question_text="Q4", correct_answer="D", points=10)
        ]
    )
    
    exam = StudentExam(
        student_name="Demo Student",
        answers=[
            StudentAnswer(question_id=1, answer="A"),
            StudentAnswer(question_id=2, answer="Wrong"),
            StudentAnswer(question_id=3, answer="C"),
            StudentAnswer(question_id=4, answer="Wrong")
        ]
    )
    
    corrector = ExamCorrector()
    corrector.load_correction_model(model)
    corrector.load_student_exam(exam)
    result = corrector.correct()
    
    print("\nResults:")
    for qr in result.question_results:
        status = "✓" if qr.is_correct else "✗"
        print(f"  Q{qr.question_id}: {status} {qr.points_awarded}/{qr.max_points} points")
    
    print(f"\nTotal Score: {result.total_points_awarded}/{result.total_possible_points}")
    print(f"Final Grade: {result.final_grade_out_of_20}/20")
    print("\nKey Observation:")
    print("  - Questions 2 and 4 are wrong, but student still gets credit for Q1 and Q3")
    print("  - NO global zero - each question is scored independently")


def demo_case_sensitivity():
    """Demonstrate case sensitivity options."""
    print("\n" + "=" * 80)
    print("DEMO: Case Sensitivity")
    print("=" * 80)
    
    model = CorrectionModel(
        exam_title="Case Sensitivity Demo",
        total_points=20,
        matching_rules=MatchingRules(case_sensitive=False),
        questions=[
            Question(
                question_id=1,
                question_text="Capital of France?",
                correct_answer="Paris",
                points=10,
                matching_type="exact"
            ),
            Question(
                question_id=2,
                question_text="What is DNA?",
                correct_answer="DNA",
                points=10,
                matching_type="exact",
                case_sensitive=True
            )
        ]
    )
    
    exam = StudentExam(
        student_name="Demo Student",
        answers=[
            StudentAnswer(question_id=1, answer="PARIS"),
            StudentAnswer(question_id=2, answer="dna")
        ]
    )
    
    corrector = ExamCorrector()
    corrector.load_correction_model(model)
    corrector.load_student_exam(exam)
    result = corrector.correct()
    
    print("\nGlobal Rule: case_sensitive = False")
    print("\nResults:")
    for qr in result.question_results:
        status = "✓" if qr.is_correct else "✗"
        print(f"\nQuestion {qr.question_id}:")
        print(f"  Student: '{qr.student_answer}' | Expected: '{qr.correct_answer}'")
        print(f"  {status} {qr.explanation}")
    
    print("\nKey Observations:")
    print("  - Q1: 'PARIS' = 'Paris' (global rule: case insensitive)")
    print("  - Q2: 'dna' ≠ 'DNA' (question override: case sensitive)")


def demo_matching_types():
    """Demonstrate different matching types."""
    print("\n" + "=" * 80)
    print("DEMO: Matching Types (exact, contains, regex)")
    print("=" * 80)
    
    model = CorrectionModel(
        exam_title="Matching Types Demo",
        total_points=30,
        questions=[
            Question(
                question_id=1,
                question_text="Exact match test",
                correct_answer="exact",
                points=10,
                matching_type="exact"
            ),
            Question(
                question_id=2,
                question_text="Contains match test",
                correct_answer="keyword",
                points=10,
                matching_type="contains"
            ),
            Question(
                question_id=3,
                question_text="Regex match test (any digit)",
                correct_answer=r"\d+",
                points=10,
                matching_type="regex"
            )
        ]
    )
    
    exam = StudentExam(
        student_name="Demo Student",
        answers=[
            StudentAnswer(question_id=1, answer="exact"),
            StudentAnswer(question_id=2, answer="The keyword is important"),
            StudentAnswer(question_id=3, answer="42")
        ]
    )
    
    corrector = ExamCorrector()
    corrector.load_correction_model(model)
    corrector.load_student_exam(exam)
    result = corrector.correct()
    
    print("\nResults:")
    for qr in result.question_results:
        status = "✓" if qr.is_correct else "✗"
        print(f"\nQuestion {qr.question_id}:")
        print(f"  Student: '{qr.student_answer}'")
        print(f"  Pattern: '{qr.correct_answer}'")
        print(f"  {status} {qr.explanation}")


def demo_generate_report():
    """Generate a PDF report."""
    print("\n" + "=" * 80)
    print("DEMO: Generate PDF Report")
    print("=" * 80)
    
    model = CorrectionModel(
        exam_title="Sample Exam for PDF Report",
        total_points=50,
        questions=[
            Question(question_id=1, question_text="What is 5+5?", correct_answer="10", points=10),
            Question(question_id=2, question_text="Capital of Japan?", correct_answer="Tokyo", points=10),
            Question(question_id=3, question_text="Color of grass?", correct_answer="green", points=10),
            Question(question_id=4, question_text="2*3=?", correct_answer="6", points=10),
            Question(question_id=5, question_text="Square root of 9?", correct_answer="3", points=10)
        ]
    )
    
    exam = StudentExam(
        student_name="Jane Doe",
        student_id="STU2024100",
        answers=[
            StudentAnswer(question_id=1, answer="10"),
            StudentAnswer(question_id=2, answer="Tokyo"),
            StudentAnswer(question_id=3, answer="green"),
            StudentAnswer(question_id=4, answer="5"),
            StudentAnswer(question_id=5, answer="3")
        ]
    )
    
    corrector = ExamCorrector()
    corrector.load_correction_model(model)
    corrector.load_student_exam(exam)
    result = corrector.correct()
    
    report_gen = ReportGenerator()
    output_path = "demo_report.pdf"
    report_gen.generate_report(result, output_path)
    
    print(f"\nPDF Report generated: {output_path}")
    print(f"Student: {result.student_name}")
    print(f"Score: {result.total_points_awarded}/{result.total_possible_points}")
    print(f"Final Grade: {result.final_grade_out_of_20}/20")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("STRICT AUTOMATIC EXAM CORRECTION SYSTEM - DEMONSTRATION")
    print("=" * 80)
    print("\nCore Principles:")
    print("  1. NO interpretation, guessing, or inference")
    print("  2. Uses ONLY the correction model provided")
    print("  3. NO synonyms (unless explicitly defined)")
    print("  4. NO partial credit (unless specified)")
    print("  5. Per-question scoring (not global zero)")
    print("  6. Deterministic and rule-based")
    
    demo_strict_correction()
    demo_per_question_scoring()
    demo_case_sensitivity()
    demo_matching_types()
    demo_generate_report()
    
    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)
    print("\nCheck the generated 'demo_report.pdf' for a sample PDF report.")
    print("\nFor more examples, see the 'examples/' directory.")
    print("For usage details, see USAGE.md")
