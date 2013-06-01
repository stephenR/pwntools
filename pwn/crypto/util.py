"""
Collection of various utility functions for cryptanalysis.
"""
from math import log10
import string

from pwn.crypto import freq
from pwn.crypto import lang
from pwn.crypto import ngram

# The expected index of coincidence value for English text
ic_english = 0.065

##############
# FORMATTING #
##############

def format_solution(ciphertext, plaintext, language=lang.English):
    """
    Format a plaintext that was cleaned and decrypted.
    The output will be formatted like the ciphertext that is passed.
    """
    i = 0
    formatted = ""
    for c in ciphertext:
        if c in language.alphabet:
           formatted += plaintext[i]
           i += 1
        else:
            formatted += c
    return formatted

################
# SCORING TEXT #
################

_lower = string.maketrans(string.ascii_lowercase, " " * len(string.ascii_lowercase))

def score_text(text, language=lang.English):
    clean = text.lower().translate(None, _lower)
    return log_p(clean, language.get_ngrams(), 3)

def score_list(texts, language=lang.English):
    scores = [score_text(t, language) for t in texts]
    return (float(sum(scores))/len(scores), texts)

def best_scoring_text(texts, language=lang.English):
    scores = [(score_text(t, language), t) for t in texts]
    return min(scores, key=lambda(s,_):s)

def best_scoring_list(lists, language=lang.English):
    scores = [score_list(l, language) for l in lists]
    return min(scores, key=lambda(s,_):s)

##################
# NGRAM ANALYSIS #
##################

def generate_ngram(text, n=3):
    """
    Generate n-gram frequency table for given text.
    """
    occurences = ngram = dict()
    for i in range(len(text) - n):
        try:
            cur = text[i:i+n]
            if cur in occurences:
                occurences[cur] += 1
            else:
                occurences[cur] = 1
        except IndexError:
            pass

    for (key,value) in occurences.items():
        ngram[key] = float(value) / (len(text) - n + 1)

    return ngram

def log_p(text, ngrams, n):
    return sum(log10(ngrams[ng]) for ng in generate_ngram(text, n).keys()) * -1.0

######################
# FREQUENCY ANALYSIS #
######################

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
