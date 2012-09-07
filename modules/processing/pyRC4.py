#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Original Author: Joao H de A Franco (jhafranco@acm.org)
# Updated by Raphaël Vinot
#
# Description: RC4 implementation in Python
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
# ===========================================================

# Global variables

state = [None] * 256
p = q = None


def __set_key(key_string):
    """RC4 Key Scheduling Algorithm (KSA)"""

    global p, q, state
    key = [ord(c) for c in key_string]
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + key[i % len(key)]) % 256
        else:
            j = (j + state[i]) % 256
        (state[i], state[j]) = (state[j], state[i])


def __byte_generator():
    """RC4 Pseudo-Random Generation Algorithm (PRGA)"""

    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    (state[p], state[q]) = (state[q], state[p])
    return state[(state[p] + state[q]) % 256]


def encrypt(key, string):
    """Encrypt input string returning a string"""
    __set_key(key)
    encrypted = [ord(p) ^ __byte_generator() for p in string]
    return ''.join(['{:02x}'.format(i) for i in encrypted])


def decrypt(key, string):
    """Decrypt input byte list returning a string"""
    __set_key(key)
    s_hex = '{:02x}'.format(int(string, 16))
    i_list = [int(s_hex[i:i + 2], 16) for i in range(0, len(s_hex), 2)]
    return ''.join([chr(c ^ __byte_generator()) for c in i_list])


