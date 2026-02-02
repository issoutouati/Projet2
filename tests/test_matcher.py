"""
Tests for the strict matching logic.
"""

import pytest
from exam_corrector.matcher import StrictMatcher
from exam_corrector.models import Question, MatchingRules


class TestStrictMatcher:
    
    def test_exact_match_case_sensitive(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Paris",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("Paris", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("paris", question)
        assert is_correct is False
        
        is_correct, explanation = matcher.match("PARIS", question)
        assert is_correct is False

    def test_exact_match_case_insensitive(self):
        rules = MatchingRules(case_sensitive=False, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Paris",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("Paris", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("paris", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("PARIS", question)
        assert is_correct is True

    def test_whitespace_handling(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Hello World",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("Hello World", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("Hello   World", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("  Hello World  ", question)
        assert is_correct is True

    def test_whitespace_not_ignored(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=False)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Hello World",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("Hello World", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("Hello  World", question)
        assert is_correct is False

    def test_contains_match(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Paris",
            points=10,
            matching_type="contains"
        )
        
        is_correct, explanation = matcher.match("The capital is Paris", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("Paris is great", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("London", question)
        assert is_correct is False

    def test_regex_match(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer=r"\d+",
            points=10,
            matching_type="regex"
        )
        
        is_correct, explanation = matcher.match("123", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("42", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("abc", question)
        assert is_correct is False

    def test_no_synonym_matching(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True, allow_synonyms=False)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="big",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("big", question)
        assert is_correct is True
        
        is_correct, explanation = matcher.match("large", question)
        assert is_correct is False

    def test_question_specific_case_sensitivity(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Paris",
            points=10,
            matching_type="exact",
            case_sensitive=False
        )
        
        is_correct, explanation = matcher.match("paris", question)
        assert is_correct is True

    def test_empty_answer(self):
        rules = MatchingRules(case_sensitive=True, ignore_whitespace=True)
        matcher = StrictMatcher(rules)
        
        question = Question(
            question_id=1,
            question_text="Test",
            correct_answer="Paris",
            points=10,
            matching_type="exact"
        )
        
        is_correct, explanation = matcher.match("", question)
        assert is_correct is False
