"""
Core exam correction logic.
Implements strict, deterministic correction following the correction model exactly.
"""

from typing import Optional
from exam_corrector.models import (
    CorrectionModel,
    StudentExam,
    CorrectionResult,
    QuestionResult,
    StudentAnswer
)
from exam_corrector.matcher import StrictMatcher


class ExamCorrector:
    """
    Main exam correction class.
    
    Behavior:
    - Deterministic: same inputs always produce same outputs
    - Strict: no interpretation or flexibility
    - Rule-based: follows only the correction model
    - Per-question scoring: each question scored independently
    """

    def __init__(self):
        self.correction_model: Optional[CorrectionModel] = None
        self.student_exam: Optional[StudentExam] = None
        self.matcher: Optional[StrictMatcher] = None

    def load_correction_model(self, model: CorrectionModel) -> None:
        """Load and validate the correction model."""
        model.validate_model()
        self.correction_model = model
        self.matcher = StrictMatcher(model.matching_rules)

    def load_student_exam(self, exam: StudentExam) -> None:
        """Load the student exam."""
        self.student_exam = exam

    def correct(self) -> CorrectionResult:
        """
        Perform strict exam correction.
        
        Rules:
        - Each question is scored independently
        - No partial credit unless explicitly defined in correction model
        - If answer doesn't match, score for that question is 0
        - Final grade is sum of all question scores converted to 0-20 scale
        
        Returns:
            CorrectionResult with detailed per-question results
            
        Raises:
            ValueError: if correction model or student exam not loaded
        """
        if self.correction_model is None:
            raise ValueError("Correction model not loaded")
        if self.student_exam is None:
            raise ValueError("Student exam not loaded")
        if self.matcher is None:
            raise ValueError("Matcher not initialized")

        answer_map = {ans.question_id: ans.answer for ans in self.student_exam.answers}
        
        question_results = []
        total_points_awarded = 0.0

        for question in self.correction_model.questions:
            student_answer = answer_map.get(question.question_id, "")
            
            if student_answer == "":
                is_correct = False
                explanation = "No answer provided - assigning 0 points"
                points_awarded = 0.0
            else:
                is_correct, explanation = self.matcher.match(student_answer, question)
                points_awarded = question.points if is_correct else 0.0

            result = QuestionResult(
                question_id=question.question_id,
                question_text=question.question_text,
                student_answer=student_answer,
                correct_answer=question.correct_answer,
                is_correct=is_correct,
                points_awarded=points_awarded,
                max_points=question.points,
                explanation=explanation
            )
            
            question_results.append(result)
            total_points_awarded += points_awarded

        percentage_score = (
            (total_points_awarded / self.correction_model.total_points) * 100.0
            if self.correction_model.total_points > 0
            else 0.0
        )
        
        final_grade = (
            (total_points_awarded / self.correction_model.total_points) * 20.0
            if self.correction_model.total_points > 0
            else 0.0
        )

        return CorrectionResult(
            exam_title=self.correction_model.exam_title,
            student_name=self.student_exam.student_name,
            student_id=self.student_exam.student_id,
            question_results=question_results,
            total_points_awarded=total_points_awarded,
            total_possible_points=self.correction_model.total_points,
            percentage_score=percentage_score,
            final_grade_out_of_20=final_grade
        )
