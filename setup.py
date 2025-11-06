#!/usr/bin/env python3
"""Setup script for Network Vector."""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read the requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="networkvector",
    version="1.0.0",
    author="ArtOfScripting",
    author_email="contact@artofscripting.com",
    description="Advanced Network Topology Scanner with Interactive D3.js Visualization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/artofscripting/networkvector",
    project_urls={
        "Bug Tracker": "https://github.com/artofscripting/networkvector/issues",
        "Documentation": "https://github.com/artofscripting/networkvector/wiki",
        "Source Code": "https://github.com/artofscripting/networkvector",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[],  # No external dependencies required
    extras_require={
        "dev": ["black", "pylint", "pytest"],
        "build": ["pyinstaller>=6.0.0"],
    },
    entry_points={
        "console_scripts": [
            "nvector=nvector:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)