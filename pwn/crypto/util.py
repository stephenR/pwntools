"""
Collection of various utility functions for cryptanalysis.
"""
import string

from pwn.crypto import freq

# The expected index of coincidence value for English text
ic_english = 0.065

def index_of_coincidence(frequencies, n):
    """
    Calculate the index of coincidence of a frequency
    distribution relative to the text length.

    Args:
        frequencies: the target frequencies to compare the text to.
        n: length of the text that the IC should be calculated for.

    Returns:
        the index of coincidence of a text of length n with the frequency
        distribution frequencies.
    """
    combinations = sum([f * (f - 1) for f in frequencies.values()])
    pairs = n * (n - 1)
    return float(combinations) / float(pairs) if pairs > 0 else 0

def expected_ic(frequencies=freq.english):
    """
    Calculate the expected index of coincidence for a text having
    the specified frequency distribution.

    Args:
        frequencies: the target frequency distribution.

    Returns:
        the expected index of coincidence for a text matching
        the frequency distribution passed
    """
    return sum([f * f for f in frequencies.values()])

def squared_differences(frequencies, expected=freq.english):
    pairs = zip(frequencies.values(), expected.values())
    return sum([(f - e) ** 2 for f,e in pairs])

def chi_squared(counts, length, expected=freq.english):
    expectedcount = {c: e * length for c,e in expected.items()}
    pairs = zip(counts.values(), expected.values())
    return sum([((c - e) ** 2) / float(e) for c,e in pairs])
