"""
Strict Automatic Exam Correction System

A deterministic, rule-based exam correction system that strictly follows
a provided correction model without interpretation or flexibility.
"""

from exam_corrector.corrector import ExamCorrector
from exam_corrector.models import CorrectionModel, StudentExam, CorrectionResult

__version__ = "1.0.0"
__all__ = ["ExamCorrector", "CorrectionModel", "StudentExam", "CorrectionResult"]
