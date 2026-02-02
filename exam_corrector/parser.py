"""
Parser module for loading correction models and student exams from various formats.
Supports JSON, text, images, and PDFs.
"""

import json
from pathlib import Path
from typing import Union
from exam_corrector.models import CorrectionModel, StudentExam, StudentAnswer, Question, MatchingRules
from exam_corrector.ocr import OCRProcessor


class InputParser:
    """
    Parses input files (correction models and student exams) from various formats.
    Supports: JSON, text files, images (via OCR), PDFs (via OCR).
    """

    def __init__(self):
        self.ocr = OCRProcessor()

    def parse_correction_model(self, file_path: Union[str, Path], use_ocr: bool = False) -> CorrectionModel:
        """
        Parse correction model from file.
        
        Args:
            file_path: Path to correction model file
            use_ocr: If True, use OCR to extract from image/PDF
            
        Returns:
            CorrectionModel object
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Correction model file not found: {file_path}")

        if use_ocr:
            if file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
                text = self.ocr.process_image(file_path)
            elif file_path.suffix.lower() == '.pdf':
                text = self.ocr.process_pdf(file_path)
            else:
                raise ValueError(f"Unsupported file format for OCR: {file_path.suffix}")
            
            data = json.loads(text)
        else:
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                raise ValueError(f"For non-OCR mode, only JSON files are supported. Got: {file_path.suffix}")

        return CorrectionModel(**data)

    def parse_student_exam(self, file_path: Union[str, Path], use_ocr: bool = False) -> StudentExam:
        """
        Parse student exam from file.
        
        Args:
            file_path: Path to student exam file
            use_ocr: If True, use OCR to extract from image/PDF
            
        Returns:
            StudentExam object
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Student exam file not found: {file_path}")

        if use_ocr:
            if file_path.suffix.lower() in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
                text = self.ocr.process_image(file_path)
            elif file_path.suffix.lower() == '.pdf':
                text = self.ocr.process_pdf(file_path)
            else:
                raise ValueError(f"Unsupported file format for OCR: {file_path.suffix}")
            
            data = json.loads(text)
        else:
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                raise ValueError(f"For non-OCR mode, only JSON files are supported. Got: {file_path.suffix}")

        return StudentExam(**data)

    def create_correction_model_from_dict(self, data: dict) -> CorrectionModel:
        """Create CorrectionModel from dictionary."""
        return CorrectionModel(**data)

    def create_student_exam_from_dict(self, data: dict) -> StudentExam:
        """Create StudentExam from dictionary."""
        return StudentExam(**data)
