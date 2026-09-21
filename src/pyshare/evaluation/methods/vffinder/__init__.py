"""VFFinder — a Python reproduction of VFFinder (ASE'24).

Identifies vulnerable functions in Python projects from a CVE description.
The package is organised by responsibility:

    extraction  — extract Attack Vector / Root Cause from the CVE text
    corpus      — build the description corpus and the function corpus
    retrieval   — match the corpora and rank candidate vulnerable functions
    common      — shared infrastructure (LLM client, NLP text helpers)

The pipeline runs extraction -> corpus -> retrieval; see README.md for the
ordered run steps. The method is language-agnostic and is applied here to
Python-project CVEs (the original paper targets Java).
"""
