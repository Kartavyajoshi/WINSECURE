"""
WinSecure Package Setup Script
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="winsecure",
    version="1.0.0",
    description="Windows Security Configuration, Compliance & Threat Exposure Assessment Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Kartavya Joshi",
    license="Apache-2.0",
    url="https://github.com/Kartavyajoshi/WINSECURE",
    packages=find_packages(include=["winsecure", "winsecure.*"]),
    include_package_data=True,
    package_data={
        "winsecure": ["*.json", "*.css", "*.js", "*.html", "reporting/templates/*"],
    },
    entry_points={
        "console_scripts": [
            "winsecure=winsecure.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
)
