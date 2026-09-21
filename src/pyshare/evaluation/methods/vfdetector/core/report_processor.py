from pyshare.evaluation.methods.vfdetector.core.code_processor import clean_text


def process_cve(description: str) -> list[str]:
    """Vulnerability-report corpus (paper Section 3.3): stopword removal +
    POS-aware WordNet lemmatization ONLY. The language-keyword removal and
    multiword splitting are source-code-corpus steps (Section 3.2), so they are
    off here — a CVE description is natural-language prose, not code."""
    return clean_text(description, remove_keywords=False, split_multiword=False)
