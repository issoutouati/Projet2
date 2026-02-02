"""
Tests for the exam corrector logic.
"""

import pytest
from exam_corrector.corrector import ExamCorrector
from exam_corrector.models import (
    CorrectionModel,
    StudentExam,
    Question,
    StudentAnswer,
    MatchingRules
)


class TestExamCorrector:
    
    def test_perfect_score(self):
        model = CorrectionModel(
            exam_title="Test Exam",
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
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="4"),
                StudentAnswer(question_id=2, answer="6")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 20.0
        assert result.final_grade_out_of_20 == 20.0
        assert result.percentage_score == 100.0
        assert all(qr.is_correct for qr in result.question_results)

    def test_zero_score(self):
        model = CorrectionModel(
            exam_title="Test Exam",
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
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="5"),
                StudentAnswer(question_id=2, answer="7")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 0.0
        assert result.final_grade_out_of_20 == 0.0
        assert result.percentage_score == 0.0
        assert all(not qr.is_correct for qr in result.question_results)

    def test_partial_score(self):
        model = CorrectionModel(
            exam_title="Test Exam",
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
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="4"),
                StudentAnswer(question_id=2, answer="7")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 10.0
        assert result.final_grade_out_of_20 == 10.0
        assert result.percentage_score == 50.0
        assert result.question_results[0].is_correct is True
        assert result.question_results[1].is_correct is False

    def test_missing_answer(self):
        model = CorrectionModel(
            exam_title="Test Exam",
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
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="4")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 10.0
        assert result.final_grade_out_of_20 == 10.0
        assert result.question_results[0].is_correct is True
        assert result.question_results[1].is_correct is False
        assert result.question_results[1].student_answer == ""

    def test_no_interpretation(self):
        model = CorrectionModel(
            exam_title="Test Exam",
            total_points=10,
            questions=[
                Question(
                    question_id=1,
                    question_text="What is the result of 10/2?",
                    correct_answer="5",
                    points=10,
                    matching_type="exact"
                )
            ]
        )
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="five")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 0.0
        assert result.question_results[0].is_correct is False

    def test_no_synonym_matching(self):
        model = CorrectionModel(
            exam_title="Test Exam",
            total_points=10,
            questions=[
                Question(
                    question_id=1,
                    question_text="Describe size",
                    correct_answer="big",
                    points=10,
                    matching_type="exact"
                )
            ]
        )
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="large")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.total_points_awarded == 0.0
        assert result.question_results[0].is_correct is False

    def test_per_question_scoring(self):
        model = CorrectionModel(
            exam_title="Test Exam",
            total_points=30,
            questions=[
                Question(
                    question_id=1,
                    question_text="Q1",
                    correct_answer="A",
                    points=10,
                    matching_type="exact"
                ),
                Question(
                    question_id=2,
                    question_text="Q2",
                    correct_answer="B",
                    points=10,
                    matching_type="exact"
                ),
                Question(
                    question_id=3,
                    question_text="Q3",
                    correct_answer="C",
                    points=10,
                    matching_type="exact"
                )
            ]
        )
        
        exam = StudentExam(
            student_name="John Doe",
            answers=[
                StudentAnswer(question_id=1, answer="A"),
                StudentAnswer(question_id=2, answer="Wrong"),
                StudentAnswer(question_id=3, answer="C")
            ]
        )
        
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        
        assert result.question_results[0].points_awarded == 10.0
        assert result.question_results[1].points_awarded == 0.0
        assert result.question_results[2].points_awarded == 10.0
        assert result.total_points_awarded == 20.0

    def test_model_not_loaded_error(self):
        corrector = ExamCorrector()
        exam = StudentExam(answers=[])
        corrector.load_student_exam(exam)
        
        with pytest.raises(ValueError, match="Correction model not loaded"):
            corrector.correct()

    def test_exam_not_loaded_error(self):
        model = CorrectionModel(
            exam_title="Test",
            total_points=10,
            questions=[
                Question(
                    question_id=1,
                    question_text="Q",
                    correct_answer="A",
                    points=10
                )
            ]
        )
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        
        with pytest.raises(ValueError, match="Student exam not loaded"):
            corrector.correct()
