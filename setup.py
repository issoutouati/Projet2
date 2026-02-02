"""
Setup configuration for Strict Automatic Exam Correction System.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="exam-corrector",
    version="1.0.0",
    author="Exam Corrector Team",
    description="A strict, deterministic automatic exam correction system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/exam-corrector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Education :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "exam-corrector=exam_corrector.cli:cli",
        ],
    },
)
