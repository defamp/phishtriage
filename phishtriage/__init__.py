"""PhishTriage — a phishing email (.eml) triage tool for SOC analysts.

Parses an email message and scores common phishing indicators: sender spoofing,
SPF/DKIM/DMARC authentication results, suspicious URLs, risky attachments and
social-engineering content — then produces a risk verdict and report.
"""

__version__ = "1.0.0"
__author__ = "Defa Mulya Pratama"
