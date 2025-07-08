"""
PcapSleuth - Network Traffic Analysis Tool
Simple version for rapid deployment
"""

__version__ = "2.0.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .core import PcapAnalysisEngine
from .models import AnalysisResult, Config

__all__ = ['PcapAnalysisEngine', 'AnalysisResult', 'Config']