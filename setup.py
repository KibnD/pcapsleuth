from setuptools import setup, find_packages
import os

# Read long description safely
long_description = "Network Traffic Analysis Tool"
try:
    if os.path.exists("README.md"):
        with open("README.md", "r", encoding="utf-8") as fh:
            long_description = fh.read()
except:
    pass

# Read requirements safely
requirements = [
    "scapy>=2.4.5",
    "click>=8.0.0",
    "tqdm>=4.64.0"
]
try:
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
except:
    pass

setup(
    name="pcapsleuth",
    version="2.0.0",
    author="KibnD",
    author_email="mr.kfibnd@example.com",
    description="Network Traffic Analysis Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/KibnD/pcapsleuth",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pcapsleuth=main:analyze",
        ],
    },
)