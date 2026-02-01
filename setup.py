#!/usr/bin/env python3
"""
ACARS Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
with open(readme_path, "r", encoding="utf-8") as f:
    long_description = f.read()

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
with open(requirements_path, "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="acars",
    version="1.0.0",
    author="ACARS Development Team",
    author_email="dev@acars.example.com",
    description="Automated Cyber Attack Response System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/acars/acars",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.1.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=3.0.0",
            "black>=22.6.0",
            "flake8>=5.0.0",
            "mypy>=0.971",
        ],
        "aws": [
            "boto3>=1.24.0",
        ],
        "azure": [
            "azure-mgmt-security>=0.5.0",
        ],
        "gcp": [
            "google-cloud-securitycenter>=1.0.0",
        ],
        "ml": [
            "tensorflow>=2.10.0",
            "torch>=1.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "acars=acars.main:main",
            "acars-cli=utils.cli:cli",
            "acars-simulate=utils.simulator:main",
        ],
    },
    include_package_data=True,
    package_data={
        "config": ["*.yaml", "*.yml"],
    },
    keywords="security cyber-attack threat-detection response automation ml",
    project_urls={
        "Bug Reports": "https://github.com/acars/acars/issues",
        "Source": "https://github.com/acars/acars",
        "Documentation": "https://acars.readthedocs.io/",
    },
)