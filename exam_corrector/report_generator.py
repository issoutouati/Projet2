"""
PDF report generator for exam correction results.
Generates detailed reports with student answers, errors, and scores.
"""

from pathlib import Path
from typing import Union
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from exam_corrector.models import CorrectionResult


class ReportGenerator:
    """
    Generates detailed PDF reports for exam correction results.
    
    Report includes:
    - Student information
    - Per-question results with answers and explanations
    - Error markings
    - Scores for each question
    - Final grade out of 20
    """

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=20,
            textColor=HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeading',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='QuestionText',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=HexColor('#34495e'),
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='AnswerText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#555555'),
            leftIndent=20
        ))
        
        self.styles.add(ParagraphStyle(
            name='ErrorText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#e74c3c'),
            leftIndent=20,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='SuccessText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=HexColor('#27ae60'),
            leftIndent=20,
            fontName='Helvetica-Bold'
        ))

    def generate_report(self, result: CorrectionResult, output_path: Union[str, Path]) -> None:
        """
        Generate a detailed PDF report.
        
        Args:
            result: CorrectionResult object containing all correction data
            output_path: Path where PDF should be saved
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )

        story = []

        story.append(Paragraph(f"{result.exam_title}", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.5*cm))

        info_data = []
        if result.student_name:
            info_data.append(['Student Name:', result.student_name])
        if result.student_id:
            info_data.append(['Student ID:', result.student_id])
        
        if info_data:
            info_table = Table(info_data, colWidths=[4*cm, 10*cm])
            info_table.setStyle(TableStyle([
                ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),
                ('FONT', (1, 0), (1, -1), 'Helvetica', 10),
                ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#2c3e50')),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 0.5*cm))

        summary_data = [
            ['Total Points Awarded:', f"{result.total_points_awarded:.2f} / {result.total_possible_points:.2f}"],
            ['Percentage Score:', f"{result.percentage_score:.2f}%"],
            ['Final Grade (out of 20):', f"{result.final_grade_out_of_20:.2f}/20"]
        ]
        
        summary_table = Table(summary_data, colWidths=[6*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 11),
            ('FONT', (1, 0), (1, -1), 'Helvetica-Bold', 11),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#2c3e50')),
            ('TEXTCOLOR', (1, 0), (1, 1), HexColor('#34495e')),
            ('TEXTCOLOR', (1, 2), (1, 2), HexColor('#e74c3c') if result.final_grade_out_of_20 < 10 else HexColor('#27ae60')),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#f8f9fa')),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 1*cm))

        story.append(Paragraph("Detailed Question Results", self.styles['SectionHeading']))
        story.append(Spacer(1, 0.3*cm))

        for i, qr in enumerate(result.question_results, 1):
            story.append(Paragraph(
                f"<b>Question {qr.question_id}:</b> {self._escape_html(qr.question_text)}",
                self.styles['QuestionText']
            ))
            
            story.append(Paragraph(
                f"<b>Student Answer:</b> {self._escape_html(qr.student_answer) if qr.student_answer else '<i>(No answer provided)</i>'}",
                self.styles['AnswerText']
            ))
            
            story.append(Paragraph(
                f"<b>Correct Answer:</b> {self._escape_html(qr.correct_answer)}",
                self.styles['AnswerText']
            ))
            
            if qr.is_correct:
                story.append(Paragraph(
                    f"✓ {qr.explanation}",
                    self.styles['SuccessText']
                ))
            else:
                story.append(Paragraph(
                    f"✗ {qr.explanation}",
                    self.styles['ErrorText']
                ))
            
            score_color = HexColor('#27ae60') if qr.is_correct else HexColor('#e74c3c')
            story.append(Paragraph(
                f"<b>Score:</b> <font color='{score_color}'>{qr.points_awarded:.2f} / {qr.max_points:.2f}</font>",
                self.styles['AnswerText']
            ))
            
            story.append(Spacer(1, 0.5*cm))
            
            if (i % 5 == 0) and (i < len(result.question_results)):
                story.append(PageBreak())

        doc.build(story)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters for ReportLab."""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
