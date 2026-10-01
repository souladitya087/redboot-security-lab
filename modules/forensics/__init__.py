"""
RedBoot Digital Forensics Module

Forensic acquisition, file carving, timeline analysis, and log correlation.
"""

from modules.forensics.carver import FileCarver, FileSignature
from modules.forensics.imager import ForensicImager
from modules.forensics.log_analyzer import LogAnalyzer
from modules.forensics.timeline import TimelineGenerator

__all__ = [
    "ForensicImager",
    "FileCarver",
    "FileSignature",
    "TimelineGenerator",
    "LogAnalyzer",
]
