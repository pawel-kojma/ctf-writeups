# Tick-tock

## Overview

The challange comprises of 2 files, the backend C program and frontend flask application.
Flask application reads in flag from GET parameter `?flag=` and passes it to C binary.
Binary is ran through [valgrind](https://valgrind.org/) to count the time it took to complete the flag verification process.
Here, side channel is possible because binary uses `strcmp` to compare flag and our input, so the more correct characters we have
the more time it will take for the process to terminate. It is also important that the challange is ran on ARM, because vectorized
SIMD instructions aren't used in strcmp implementation.

## Solution

We start with `flag` being `ping{` and bruteforce every pair of characters from the alphabet (organizers provided flag characters "13457unsdchr_").
If current flag character is `x` then all pairs that start with `x` will stand out, because `x` was correct and `strcmp` started comparing another character. In case of other pairs, `strcmp` will terminate sooner and input will take less time to process.

We just accept the first character of pair, that took the longest to process, as another flag character. We loop until flag is complete.

Provided `solve.py` script brutforces the flag.
Unfortunately, I had bad internet connection on the train at that time and didn't solve it in time :(

