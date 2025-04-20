#!/usr/bin/env python3

# state if initial seed is 1337
# change last dword to provided one
STATE = [0x7777724E, 0x000007E5, 0x7FFFFFFF, 0x6d0abcb3]


def mask_u32(x):
    return x & 0xFFFFFFFF


def update_state():
    global STATE
    STATE[3] = mask_u32(STATE[0] * STATE[3] + STATE[1]) % STATE[2]
    return STATE[3]


def shuffle_cards():
    deck_str = [
        "sA",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
        "s9",
        "sX",
        "sJ",
        "sQ",
        "sK",
        "hA",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "h7",
        "h8",
        "h9",
        "hX",
        "hJ",
        "hQ",
        "hK",
        "cA",
        "c2",
        "c3",
        "c4",
        "c5",
        "c6",
        "c7",
        "c8",
        "c9",
        "cX",
        "cJ",
        "cQ",
        "cK",
        "dA",
        "d2",
        "d3",
        "d4",
        "d5",
        "d6",
        "d7",
        "d8",
        "d9",
        "dX",
        "dJ",
        "dQ",
        "dK",
    ]
    deck = list(range(52))
    lvar3 = 0x33
    while lvar3 != 0:
        uvar2 = update_state() % (lvar3 + 1)
        deck[lvar3], deck[uvar2] = deck[uvar2], deck[lvar3]
        lvar3 -= 1
    print(" ".join(deck_str[x] for x in deck))


if __name__ == "__main__":
    shuffle_cards()
