"""
Command-line interface for the exam correction system.
"""

import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from exam_corrector.corrector import ExamCorrector
from exam_corrector.parser import InputParser
from exam_corrector.report_generator import ReportGenerator

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Strict Automatic Exam Correction System"""
    pass


@cli.command()
@click.option(
    '--correction-model',
    '-c',
    required=True,
    type=click.Path(exists=True),
    help='Path to correction model file (JSON, or image/PDF with --use-ocr)'
)
@click.option(
    '--student-exam',
    '-s',
    required=True,
    type=click.Path(exists=True),
    help='Path to student exam file (JSON, or image/PDF with --use-ocr)'
)
@click.option(
    '--output',
    '-o',
    required=True,
    type=click.Path(),
    help='Output path for PDF report'
)
@click.option(
    '--use-ocr',
    is_flag=True,
    help='Use OCR to extract text from images/PDFs'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Display detailed results in console'
)
def correct(correction_model: str, student_exam: str, output: str, use_ocr: bool, verbose: bool):
    """
    Correct an exam using the strict correction model.
    
    This system:
    - Follows only the correction model provided
    - Does not interpret, guess, or infer answers
    - Assigns 0 points for non-matching answers
    - Scores each question independently
    - Generates a detailed PDF report
    """
    try:
        console.print("\n[bold cyan]Strict Automatic Exam Correction System[/bold cyan]\n")
        
        console.print("[yellow]Loading correction model...[/yellow]")
        parser = InputParser()
        model = parser.parse_correction_model(correction_model, use_ocr=use_ocr)
        console.print(f"[green]✓[/green] Loaded: {model.exam_title}")
        console.print(f"  Total points: {model.total_points}")
        console.print(f"  Questions: {len(model.questions)}")
        
        console.print("\n[yellow]Loading student exam...[/yellow]")
        exam = parser.parse_student_exam(student_exam, use_ocr=use_ocr)
        console.print(f"[green]✓[/green] Loaded student exam")
        if exam.student_name:
            console.print(f"  Student: {exam.student_name}")
        if exam.student_id:
            console.print(f"  ID: {exam.student_id}")
        console.print(f"  Answers: {len(exam.answers)}")
        
        console.print("\n[yellow]Performing strict correction...[/yellow]")
        corrector = ExamCorrector()
        corrector.load_correction_model(model)
        corrector.load_student_exam(exam)
        result = corrector.correct()
        console.print("[green]✓[/green] Correction complete")
        
        if verbose:
            _display_results(result)
        
        console.print("\n[yellow]Generating PDF report...[/yellow]")
        report_gen = ReportGenerator()
        report_gen.generate_report(result, output)
        console.print(f"[green]✓[/green] Report saved to: {output}")
        
        console.print("\n[bold green]Summary:[/bold green]")
        console.print(f"  Score: {result.total_points_awarded:.2f} / {result.total_possible_points:.2f}")
        console.print(f"  Percentage: {result.percentage_score:.2f}%")
        console.print(f"  Final Grade: [bold]{result.final_grade_out_of_20:.2f}/20[/bold]")
        
        if result.final_grade_out_of_20 >= 10:
            console.print("\n[bold green]✓ PASSED[/bold green]")
        else:
            console.print("\n[bold red]✗ FAILED[/bold red]")
        
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        raise click.Abort()


@cli.command()
@click.argument('output_path', type=click.Path())
def create_template(output_path: str):
    """Create a template correction model JSON file."""
    template = {
        "exam_title": "Sample Exam",
        "total_points": 100,
        "matching_rules": {
            "case_sensitive": True,
            "ignore_whitespace": True,
            "allow_synonyms": False
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
                "question_text": "What is the capital of France?",
                "correct_answer": "Paris",
                "points": 10,
                "matching_type": "exact"
            }
        ]
    }
    
    import json
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(template, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]✓[/green] Template created at: {output_path}")


def _display_results(result):
    """Display detailed results in console."""
    console.print("\n[bold]Detailed Results:[/bold]\n")
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Q#", style="dim", width=4)
    table.add_column("Student Answer", width=20)
    table.add_column("Correct Answer", width=20)
    table.add_column("Status", width=10)
    table.add_column("Score", justify="right", width=10)
    
    for qr in result.question_results:
        status = "[green]✓[/green]" if qr.is_correct else "[red]✗[/red]"
        score_text = f"{qr.points_awarded:.1f}/{qr.max_points:.1f}"
        
        student_ans = qr.student_answer[:17] + "..." if len(qr.student_answer) > 20 else qr.student_answer
        correct_ans = qr.correct_answer[:17] + "..." if len(qr.correct_answer) > 20 else qr.correct_answer
        
        table.add_row(
            str(qr.question_id),
            student_ans if student_ans else "(empty)",
            correct_ans,
            status,
            score_text
        )
    
    console.print(table)


if __name__ == '__main__':
    cli()
