"""
Utilities for modern cryptanalysis.
"""

import string, collections, os, signal
import gmpy
from functools import wraps
from itertools import *
from random import seed, randint
from sympy.solvers import solve
from sympy.core import numbers
from sympy import Symbol
from fractions import Fraction

from pwn.crypto import freq

class TimeoutError(Exception):
    pass

# Timeout decorator
def timeout(seconds=10, error_message=""):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator

@timeout(10)
def factor_fermat(N):
    """
    Guess at a and hope that a^2 - N = b^2,
    which is the case if p and q is "too close".
    """
    a  = gmpy.sqrt(N)
    b2 = a*a - N
    while not gmpy.is_square(gmpy.mpz(b2)):
        b2 += 2*a + 1
        a  += 1

    factor1 = a - gmpy.sqrt(b2)
    factor2 = a + gmpy.sqrt(b2)
    return (int(factor1.digits()),int(factor2.digits()))

@timeout(10)
def factor_pollard_rho(N):
    """
    Pollard's rho algorithm for factoring numbers,
    implemented using Brent's cycle finding algorithm.
    """
    i = 1
    power = 2
    x = y = 2
    d = 1

    while d == 1:
        i += 1
        x = (x * x + 2) % N
        d = gcd(abs(x - y), N)

        if i == power:
            y = x
            power *= 2

    if d != N: return (d, N // d) # Whaat?
    else: return None

def factor(N):
    """Try to factor a number by running through all factoring algorithms"""
    algos = [factor_fermat, factor_pollard_rho]
    for alg in algos:
        try: return alg(N)
        except TimeoutError: continue
    return None

def totient(p,q):
    """Eulers totient function"""
    return (p-1)*(q-1)

def egcd(a, b):
    """Extended greatest common denominator function"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(b, p):
    """Greatest common denominator (Euclids algorithm)"""
    return egcd(b, p)[0]

def modinv(a, m):
    """Modular multiplicative inverse, i.e. a^-1 = 1 (mod m)"""
    a, u, v = egcd(a, m)
    if a <> 1:
        raise Exception('No inverse: %d (mod %d)' % (b, p))
    return u

def crt(a, n):
    """Solve Chinese remainder theorem, eg. determine x in
    a[0] = x       ( n[0] )
    ...
    a[-1] = x      ( n[-1] )

    Elements in n must be pairwise co-prime"""
    M = reduce(operator.mul, lm)
    # print M
    lM = [M/mi for mi in lm]
    ly = map(invmod, lM, lm)
    laMy = map((lambda ai, Mi, yi : ai*Mi*yi), la, lM, ly)
    return sum(laMy) % M

def reste_chinois(a, n):
    """Alias for crt"""
    return crt(a, n)

def fast_exponentiation(a, p, n):
    """A fast way to calculate a**p % n"""
    result = a%n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result

def gcd_step(a, b):
    """
    Performs a single step of the gcd algorithm.
    Example: gcd_step(1071, 462) == (2, 147) because 1071 == 2 * 462 + 147.
    """
    if a < b:
        return (0, b)

    res = 0
    while a >= b:
        a -= b
        res += 1
    return (res, a)

def continued_fractions(a, b, limit = -1):
    """
    Calculates continued fraction representation of a/b up to limit accuracy.
    """
    continued_fractions = []
    if b < a:
        continued_fractions.append(0)

    while True:
        (integer, rest) = gcd_step(a,b)
        continued_fractions.append(integer)

        if rest == 0 or limit == 0:
            break
        elif limit > 0:
            limit -= 1
        else:
            a = b
            b = rest
    return continued_fractions

def calculate_fraction(fs):
    """
    Calculate fraction from continued fraction list.
    Might need result.limit_denominator() for best results.
    """
    if len(fs) == 1:
        return Fraction(fs[0])
    else:
        return Fraction(fs[0] + 1. / calculate_fraction(fs[1:]))
