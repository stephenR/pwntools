from os import path
import string

from pwn import read

class Language:
    alphabet = string.ascii_uppercase
    # Values for scoring text based on frequency distributions
    expected_ic = None
    frequencies = None
    # Resources for scoring text based on N-grams
    ngrams_file = "english_3.txt"
    ngrams = None

    @classmethod
    def get_ngrams(cls):
        if cls.ngrams == None:
            resource_dir = path.dirname(__file__)
            ngrams_location = path.join(resource_dir, cls.ngrams_file)
            data = read(ngrams_location).split()
            total = sum(map(int, data[1::2])) * 1.
            cls.ngrams = dict(zip(data[0::2], [int(x) / total for x in data[1::2]]))
        return cls.ngrams

class English(Language):
    alphabet = string.ascii_uppercase
    # Values for scoring text based on frequency distributions
    expected_ic = 0.065
    frequencies = {
        'A' : 0.082,
        'B' : 0.015,
        'C' : 0.028,
        'D' : 0.043,
        'E' : 0.126,
        'F' : 0.022,
        'G' : 0.020,
        'H' : 0.061,
        'I' : 0.070,
        'J' : 0.002,
        'K' : 0.008,
        'L' : 0.040,
        'M' : 0.024,
        'N' : 0.067,
        'O' : 0.075,
        'P' : 0.019,
        'Q' : 0.001,
        'R' : 0.060,
        'S' : 0.063,
        'T' : 0.091,
        'U' : 0.028,
        'V' : 0.010,
        'W' : 0.023,
        'X' : 0.001,
        'Y' : 0.020,
        'Z' : 0.001
    }
    # Resources for scoring text based on N-grams
    ngrams_file = "english_3.txt"
