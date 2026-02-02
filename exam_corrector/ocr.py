"""
OCR module for extracting text from images and PDFs.
Used when correction model or student exam is provided as image/PDF.
"""

import io
from typing import Union, List
from pathlib import Path
from PIL import Image
import pytesseract


class OCRProcessor:
    """
    Handles OCR processing for images and PDFs.
    Converts visual content to text for strict matching.
    """

    def __init__(self, lang: str = "eng"):
        self.lang = lang

    def process_image(self, image_path: Union[str, Path]) -> str:
        """
        Extract text from an image file.
        
        Args:
            image_path: Path to image file
            
        Returns:
            Extracted text
        """
        try:
            image = Image.open(image_path)
            text = pytesseract.image_to_string(image, lang=self.lang)
            return text.strip()
        except Exception as e:
            raise ValueError(f"Failed to process image: {str(e)}")

    def process_pdf(self, pdf_path: Union[str, Path]) -> str:
        """
        Extract text from a PDF file.
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            Extracted text from all pages
        """
        try:
            from pdf2image import convert_from_path
            
            images = convert_from_path(pdf_path)
            
            text_parts = []
            for image in images:
                text = pytesseract.image_to_string(image, lang=self.lang)
                text_parts.append(text.strip())
            
            return "\n".join(text_parts)
        except Exception as e:
            raise ValueError(f"Failed to process PDF: {str(e)}")

    def process_image_bytes(self, image_bytes: bytes) -> str:
        """
        Extract text from image bytes.
        
        Args:
            image_bytes: Image data as bytes
            
        Returns:
            Extracted text
        """
        try:
            image = Image.open(io.BytesIO(image_bytes))
            text = pytesseract.image_to_string(image, lang=self.lang)
            return text.strip()
        except Exception as e:
            raise ValueError(f"Failed to process image bytes: {str(e)}")
