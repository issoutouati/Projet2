"""
Strict answer matching logic.
This module implements deterministic matching without interpretation.
"""

import re
from typing import Tuple
from exam_corrector.models import Question, MatchingRules


class StrictMatcher:
    """
    Implements strict, deterministic answer matching.
    No interpretation, guessing, or flexibility allowed.
    """

    def __init__(self, matching_rules: MatchingRules):
        self.global_rules = matching_rules

    def match(self, student_answer: str, question: Question) -> Tuple[bool, str]:
        """
        Match student answer against correct answer.
        
        Returns:
            Tuple[bool, str]: (is_correct, explanation)
        """
        correct_answer = question.correct_answer
        
        case_sensitive = (
            question.case_sensitive 
            if question.case_sensitive is not None 
            else self.global_rules.case_sensitive
        )
        ignore_whitespace = (
            question.ignore_whitespace
            if question.ignore_whitespace is not None
            else self.global_rules.ignore_whitespace
        )

        student_processed = self._preprocess(student_answer, case_sensitive, ignore_whitespace)
        correct_processed = self._preprocess(correct_answer, case_sensitive, ignore_whitespace)

        if question.matching_type == "exact":
            return self._exact_match(student_processed, correct_processed)
        elif question.matching_type == "contains":
            return self._contains_match(student_processed, correct_processed)
        elif question.matching_type == "regex":
            return self._regex_match(student_processed, correct_answer)
        else:
            return False, f"Unknown matching type: {question.matching_type}"

    def _preprocess(self, text: str, case_sensitive: bool, ignore_whitespace: bool) -> str:
        """Preprocess text according to matching rules."""
        processed = text
        
        if not case_sensitive:
            processed = processed.lower()
        
        if ignore_whitespace:
            processed = ' '.join(processed.split())
        
        return processed

    def _exact_match(self, student_answer: str, correct_answer: str) -> Tuple[bool, str]:
        """Perform exact string matching."""
        if student_answer == correct_answer:
            return True, "Answer matches the correction model exactly"
        else:
            return False, "Answer does not match the correction model"

    def _contains_match(self, student_answer: str, correct_answer: str) -> Tuple[bool, str]:
        """Check if student answer contains the correct answer."""
        if correct_answer in student_answer:
            return True, "Answer contains the expected text from correction model"
        else:
            return False, "Answer does not contain the expected text from correction model"

    def _regex_match(self, student_answer: str, pattern: str) -> Tuple[bool, str]:
        """
        Match using regex pattern.
        In case of invalid regex, always return False (strictest interpretation).
        """
        try:
            if re.fullmatch(pattern, student_answer):
                return True, "Answer matches the correction model pattern"
            else:
                return False, "Answer does not match the correction model pattern"
        except re.error:
            return False, "Invalid regex pattern in correction model - assigning 0 points"
