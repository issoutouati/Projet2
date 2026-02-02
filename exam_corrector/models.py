"""
Data models for the exam correction system.
All models are strict and deterministic.
"""

from typing import List, Dict, Optional, Literal
from pydantic import BaseModel, Field


class MatchingRules(BaseModel):
    case_sensitive: bool = True
    ignore_whitespace: bool = True
    allow_synonyms: bool = False
    synonyms: Optional[Dict[str, List[str]]] = None


class Question(BaseModel):
    question_id: int
    question_text: str
    correct_answer: str
    points: float
    matching_type: Literal["exact", "contains", "regex"] = "exact"
    case_sensitive: Optional[bool] = None
    ignore_whitespace: Optional[bool] = None


class CorrectionModel(BaseModel):
    exam_title: str
    total_points: float
    matching_rules: MatchingRules = Field(default_factory=MatchingRules)
    questions: List[Question]

    def validate_model(self) -> None:
        total = sum(q.points for q in self.questions)
        if abs(total - self.total_points) > 0.01:
            raise ValueError(
                f"Sum of question points ({total}) does not match total_points ({self.total_points})"
            )


class StudentAnswer(BaseModel):
    question_id: int
    answer: str


class StudentExam(BaseModel):
    student_name: Optional[str] = None
    student_id: Optional[str] = None
    answers: List[StudentAnswer]


class QuestionResult(BaseModel):
    question_id: int
    question_text: str
    student_answer: str
    correct_answer: str
    is_correct: bool
    points_awarded: float
    max_points: float
    explanation: str


class CorrectionResult(BaseModel):
    exam_title: str
    student_name: Optional[str] = None
    student_id: Optional[str] = None
    question_results: List[QuestionResult]
    total_points_awarded: float
    total_possible_points: float
    percentage_score: float
    final_grade_out_of_20: float
    
    def calculate_final_grade(self) -> float:
        if self.total_possible_points == 0:
            return 0.0
        return (self.total_points_awarded / self.total_possible_points) * 20.0
