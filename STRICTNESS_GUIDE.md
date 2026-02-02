# Strictness Guide - Understanding the System's Behavior

This document explains exactly how the Strict Automatic Exam Correction System operates and what "strict" means in practice.

## Core Philosophy

This system is a **deterministic rule-based grader**, not a teacher or intelligent assistant. It:

- Acts like a simple string-matching machine
- Has zero understanding of meaning or context
- Cannot interpret, infer, or guess
- Follows only the explicit rules you provide

Think of it as a very precise robot that can only do exact comparisons.

## What "Strict" Means

### 1. No Interpretation

The system does not understand what answers mean. It only compares strings.

**Example:**
```
Question: "What is 2+2?"
Correct Answer: "4"

Student Answers:
✓ "4"           → CORRECT (exact match)
✗ "four"        → INCORRECT (different string)
✗ "4.0"         → INCORRECT (different string)
✗ "04"          → INCORRECT (different string)
✗ "Four"        → INCORRECT (different string)
✗ "2+2=4"       → INCORRECT (different string)
✗ "The answer is 4" → INCORRECT (different string)
```

Even though "four", "4.0", and "2+2=4" are all logically correct, they don't match the string "4" exactly, so they are marked wrong.

### 2. No Synonyms

The system does not know that words can have similar meanings.

**Example:**
```
Question: "Describe something large"
Correct Answer: "big"

Student Answers:
✓ "big"         → CORRECT (exact match)
✗ "large"       → INCORRECT (different word)
✗ "huge"        → INCORRECT (different word)
✗ "enormous"    → INCORRECT (different word)
✗ "Big"         → INCORRECT (different case, if case_sensitive=true)
```

### 3. No External Knowledge

The system does not know facts about the world. It only knows what's in the correction model.

**Example:**
```
Question: "Capital of France?"
Correct Answer: "Paris"

Student Answers:
✓ "Paris"       → CORRECT
✗ "Paris, France" → INCORRECT (extra text)
✗ "paris"       → INCORRECT (if case_sensitive=true)
```

Even if the student provides more information or context, it doesn't match the expected string exactly.

### 4. No Partial Credit

Unless explicitly configured in the correction model, there is no partial credit. An answer is either completely right or completely wrong.

**Example:**
```
Question: "List three colors"
Correct Answer: "red, blue, green"
Points: 10

Student Answers:
✓ "red, blue, green"     → 10/10 points
✗ "red, blue, yellow"    → 0/10 points (not exact match)
✗ "red, blue"            → 0/10 points (not exact match)
```

There is no "partial credit" for getting 2 out of 3 colors correct.

### 5. Per-Question Scoring

**IMPORTANT:** Wrong answers only affect the question they're answering, not the entire exam.

**Example:**
```
Exam:
  Q1: 10 points - Student gets WRONG
  Q2: 10 points - Student gets CORRECT
  Q3: 10 points - Student gets CORRECT
  
Result:
  Q1: 0/10 points
  Q2: 10/10 points
  Q3: 10/10 points
  Total: 20/30 points
  Final Grade: 13.33/20
```

The student does NOT get a global zero. Each question is independent.

## When Ambiguity Occurs

When there's any ambiguity or uncertainty, the system **always chooses the strictest interpretation** and assigns 0 points.

**Examples:**
- Invalid regex pattern → 0 points
- Question ID mismatch → 0 points
- Missing answer → 0 points
- OCR errors → May result in 0 points if text doesn't match

## Configuration Options

You CAN control some aspects of strictness:

### Case Sensitivity

```json
{
  "matching_rules": {
    "case_sensitive": false
  }
}
```

- `true`: "Paris" ≠ "paris"
- `false`: "Paris" = "paris"

### Whitespace Handling

```json
{
  "matching_rules": {
    "ignore_whitespace": true
  }
}
```

- `true`: "Hello  World" = "Hello World"
- `false`: "Hello  World" ≠ "Hello World"

### Matching Types

#### Exact Match
```json
{
  "matching_type": "exact"
}
```
Student answer must match exactly (after applying case/whitespace rules).

#### Contains Match
```json
{
  "matching_type": "contains"
}
```
Student answer must contain the correct answer as a substring.

Example:
- Correct: "Paris"
- "Paris" → ✓
- "The capital is Paris" → ✓
- "London" → ✗

#### Regex Match
```json
{
  "matching_type": "regex",
  "correct_answer": "\\d+"
}
```
Student answer must match the regex pattern.

Example:
- Pattern: `\d+` (any digits)
- "123" → ✓
- "42" → ✓
- "abc" → ✗

## Common Pitfalls

### 1. Expecting Intelligence

**DON'T EXPECT:**
- "The student obviously meant X"
- "This is essentially the same answer"
- "That's just a typo"

**THE SYSTEM:**
- Cannot read minds
- Cannot determine intent
- Cannot forgive typos

### 2. Expecting Flexibility

**DON'T EXPECT:**
- Multiple acceptable answers (unless you use regex)
- "Close enough" matching
- Alternative valid responses

**SOLUTION:**
- Define regex patterns for multiple valid answers
- Use `contains` matching if substring is sufficient
- Be very explicit in your correction model

### 3. Expecting Context Understanding

**DON'T EXPECT:**
- "2+2" and "4" to be recognized as equivalent
- "USA" and "United States" to be treated the same
- Unit conversions (1m ≠ 100cm)

**SOLUTION:**
- Define exactly what format you expect
- Be explicit in the correct answer
- Use regex if multiple formats are acceptable

## Best Practices

### 1. Be Explicit

❌ Bad: Expected answer: "big"
✅ Good: Tell students: "Answer must be exactly 'big' (lowercase)"

### 2. Test Your Model

Before using with real students:
```bash
# Create test exam with various answers
# Run correction
# Verify results match your expectations
```

### 3. Define Clear Rules

Share with students:
- Case sensitivity requirements
- Exact format expected
- Whether whitespace matters
- Examples of correct answers

### 4. Use Appropriate Matching

- **Exact match**: For objective answers (numbers, codes, specific terms)
- **Contains match**: For answers that must include a keyword
- **Regex match**: For answers with multiple valid formats

### 5. Validate Total Points

```json
{
  "total_points": 100,
  "questions": [
    {"points": 50},
    {"points": 50}
  ]
}
```

Make sure question points sum to total_points.

## Examples of Strict Behavior

### Example 1: Mathematical Answer

```
Question: "What is 10/2?"
Correct Answer: "5"

Results:
✓ "5"
✗ "5.0"
✗ "five"
✗ "5 "  (if ignore_whitespace=false)
✗ "05"
```

### Example 2: Text Answer

```
Question: "Name a programming language"
Correct Answer: "Python"
Matching: exact, case_sensitive=true

Results:
✓ "Python"
✗ "python"
✗ "PYTHON"
✗ "Python3"
✗ "Python programming language"
```

### Example 3: Contains Matching

```
Question: "Write a sentence containing the word 'algorithm'"
Correct Answer: "algorithm"
Matching: contains, case_sensitive=false

Results:
✓ "An algorithm is a set of steps"
✓ "I love algorithms"
✓ "ALGORITHM"
✗ "An algo is great" (doesn't contain full word)
```

### Example 4: Regex Matching

```
Question: "Enter a valid email"
Correct Answer: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
Matching: regex

Results:
✓ "user@example.com"
✓ "test.user+tag@domain.co.uk"
✗ "notanemail"
✗ "missing@domain"
```

## When to Use This System

**IDEAL FOR:**
- ✓ Objective exams with clear right/wrong answers
- ✓ Code/syntax testing (exact format required)
- ✓ Multiple choice (with text answers)
- ✓ Standardized tests
- ✓ When you want zero ambiguity

**NOT IDEAL FOR:**
- ✗ Essay questions
- ✗ Open-ended responses
- ✗ Creative writing
- ✗ Answers that need interpretation
- ✗ When you want flexible grading

## Summary

This system is intentionally strict and inflexible. It:

1. **Matches strings, not meanings**
2. **Follows rules, not logic**
3. **Compares text, not understanding**
4. **Enforces exactness, not similarity**

If you need flexibility, interpretation, or understanding, this system is not appropriate. It is designed for scenarios where you need strict, deterministic, rule-based correction with zero ambiguity or interpretation.

## Questions?

- "Can I make it accept synonyms?" → No, but you can use regex with alternatives: `(big|large|huge)`
- "Can it understand meaning?" → No, it only compares strings
- "Will it give partial credit?" → No, unless you define multiple questions
- "Can it be more lenient?" → You can adjust case sensitivity and whitespace, but it will always be exact within those rules

The system does exactly what you tell it to do, nothing more, nothing less.
