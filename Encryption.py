"""
@Author: Zhang Mengting
@School: Xidian University
@Reference: https://zhuanlan.zhihu.com/p/78913397
This module is to implement AES algorithm.
"""

import sys
from functools import reduce
from operator import xor, add
import random


# Just a static class to hide methods in every step.
class Encryption:
    IV = (random.randint(0, 2 ** 32 - 1)).to_bytes(16, sys.byteorder)
    S_table = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    )

    reverse_S_table = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    )

    mix_array = (
        (0x02, 0x03, 0x01, 0x01),
        (0x01, 0x02, 0x03, 0x01),
        (0x01, 0x01, 0x02, 0x03),
        (0x03, 0x01, 0x01, 0x02)
    )

    reversed_mix_array = (
        (0x0E, 0x0B, 0x0D, 0x09),
        (0x09, 0x0E, 0x0B, 0x0D),
        (0x0D, 0x09, 0x0E, 0x0B),
        (0x0B, 0x0D, 0x09, 0x0E)
    )

    RC = (0X00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

    def __init__(self):
        super(object, self).__init__()

    @staticmethod
    def get_encryption_result(plain_text, key, show_middle_result=False):
        plain_text_bytes = plain_text.encode("utf-8")
        # Now process bytes.
        plain_text_bytes = Encryption.__PKCS_7_padding(plain_text_bytes)
        plain_text_bytes_num = len(plain_text_bytes)
        key_bytes = key.encode("utf-8")
        key_bytes_num = len(key_bytes)
        if key_bytes_num * 8 != 128:
            raise Exception("The length of key must be 128 bits.")
        if show_middle_result:
            print("The text after padding is: {}".format(plain_text_bytes))

        keys = Encryption.__key_generation(key_bytes)
        # CBC mode
        cipher_part = Encryption.IV
        cipher_text = b""
        for start in range(0, plain_text_bytes_num, 16):
            plain_part = plain_text_bytes[start:start + 16]
            CBC_text = b""
            for i in range(16):
                CBC_text += (plain_part[i] ^ cipher_part[i]).to_bytes(1, sys.byteorder)
            # CBC text is the text plaintext xor last ciphertext
            round_input = Encryption.__add_round_key(CBC_text, keys[0])
            for round_num in range(10):
                S_substitution_result = Encryption.__plain_S_substitution(round_input, reverse=False)
                shift_rows_result = Encryption.__shift_rows(S_substitution_result, reverse=False)
                # Do not mix col at round 10.
                if round_num != 9:
                    mix_columns_result = Encryption.__mix_columns(shift_rows_result, reverse=False)
                else:
                    mix_columns_result = b""
                    for col in range(4):
                        for row in range(4):
                            mix_columns_result += shift_rows_result[col][row].to_bytes(1, byteorder=sys.byteorder)
                add_round_key_result = Encryption.__add_round_key(mix_columns_result, keys[round_num + 1])
                round_input = add_round_key_result
                cipher_part = b""
                for col in range(4):
                    for row in range(4):
                        cipher_part += add_round_key_result[col][row].to_bytes(1, byteorder=sys.byteorder)

                if show_middle_result:
                    print("The middle result after {}th encryption round is {}".format(round_num, cipher_part))
            cipher_text += cipher_part

        return cipher_text

    @staticmethod
    def get_decryption_result(cipher_text, key, show_middle_result=False):
        key_bytes = key.encode("utf-8")
        key_bytes_num = len(key_bytes)
        if key_bytes_num * 8 != 128:
            raise Exception("The length of key must be 128 bits.")
        keys = Encryption.__key_generation(key_bytes)

        cipher_text_bytes_num = len(cipher_text)
        # CBC mode
        last_cipher = Encryption.IV
        plain_text = b""
        for start in range(0, cipher_text_bytes_num, 16):
            cipher_part = cipher_text[start:start + 16]
            round_input = cipher_part
            for round_num in range(10):
                add_round_key_result = Encryption.__add_round_key(round_input, keys[10 - round_num])

                # Do not mix col at round 10.
                if round_num != 0:
                    reversed_mix_columns_result = Encryption.__mix_columns(add_round_key_result, reverse=True)
                else:
                    reversed_mix_columns_result = add_round_key_result
                reversed_shift_rows_result = Encryption.__shift_rows(reversed_mix_columns_result, reverse=True)
                reverse_S_substitution_result = Encryption.__plain_S_substitution(reversed_shift_rows_result,
                                                                                  reverse=True)
                round_input = b""
                for col in range(4):
                    for row in range(4):
                        round_input += reverse_S_substitution_result[col][row].to_bytes(1, byteorder=sys.byteorder)

                if show_middle_result:
                    print("The middle result after {}th decryption round is {}".format(round_num, round_input))
            add_round_key_result = Encryption.__add_round_key(round_input, keys[0])
            round_input = b""
            for col in range(4):
                for row in range(4):
                    round_input += add_round_key_result[col][row].to_bytes(1, byteorder=sys.byteorder)
            CBC_text = b""
            for i in range(16):
                CBC_text += (last_cipher[i] ^ round_input[i]).to_bytes(1, sys.byteorder)
            # CBC text is the text ciphertext xor last plaintext
            plain_part = CBC_text
            last_cipher = cipher_part
            plain_text += plain_part
        return Encryption.__remove_PKCS_7_padding(plain_text)

    @staticmethod
    def __PKCS_7_padding(plain_text_bytes):
        plain_text_bytes_num = len(plain_text_bytes)
        # When just fit, add one more group
        to_add_num = 16 - plain_text_bytes_num % 16
        for _ in range(to_add_num):
            plain_text_bytes += to_add_num.to_bytes(1, byteorder=sys.byteorder)
        if len(plain_text_bytes) % 16 != 0:
            raise Exception("Wrong padding!")

        return plain_text_bytes

    @staticmethod
    def __add_round_key(CBC_text, key):
        main_matrix = []
        for row in range(4):
            tmp_matrix = []
            for index in range(row * 4, row * 4 + 4):
                tmp_matrix.append(CBC_text[index] ^ key[index])
            main_matrix.append(tmp_matrix)

        return main_matrix

    @staticmethod
    def __plain_S_substitution(matrix, reverse):
        if reverse:
            S_table = Encryption.reverse_S_table
        else:
            S_table = Encryption.S_table
        main_matrix = []
        for sub_matrix in matrix:
            tmp = []
            for i in sub_matrix:
                tmp.append(S_table[i])
            main_matrix.append(tmp)

        return main_matrix

    @staticmethod
    def __shift_rows(matrix, reverse):
        main_matrix = [[], [], [], []]
        if reverse:
            for shift_num in range(4):
                main_matrix[shift_num] = matrix[shift_num][-shift_num:] + matrix[shift_num][:-shift_num]
        else:
            for shift_num in range(4):
                main_matrix[shift_num] = matrix[shift_num][shift_num:] + matrix[shift_num][:shift_num]

        return main_matrix

    @staticmethod
    def __mix_columns(matrix, reverse):
        if reverse:
            col_mix_array = Encryption.reversed_mix_array
        else:
            col_mix_array = Encryption.mix_array
        main_matrix = []
        for row in range(4):
            tmp = []
            for col in range(4):
                # Like normal matrix mul.
                tmp.append(reduce(xor,
                                  [Encryption.__galois_multiplication(col_mix_array[row][i], matrix[i][col])
                                   for i in range(4)]))
            main_matrix.append(tmp)

        if not reverse:
            result = b""
            for col in range(4):
                for row in range(4):
                    result += main_matrix[col][row].to_bytes(1, byteorder=sys.byteorder)
            return result

        return main_matrix

    @staticmethod
    def __galois_multiplication(x, y):
        tmp = [x]

        for i in range(1, 8):
            tmp.append(Encryption.__x_time(tmp[i - 1]))
        tmp_mul = Encryption.__to_8bit((y & 0X01) * x)

        for i in range(1, 8):
            tmp_mul ^= Encryption.__to_8bit(((y >> i) & 0X01) * tmp[i])

        return tmp_mul

    # Reference: https://blog.csdn.net/bupt073114/article/details/27382533
    @staticmethod
    def __x_time(x):
        return Encryption.__to_8bit((x << 1) ^ (0X1B if x & 0X80 else 0X00))

    @staticmethod
    def __to_8bit(x):
        return int(bin(x)[2:][-8:], 2)

    @staticmethod
    def __key_generation(key_bytes):

        key_words = [key_bytes[i:i + 4] for i in range(4)]

        for i in range(4, 44):
            tmp = b""
            if i % 4 == 0:
                g_w = Encryption.__g_fun(key_words[i - 1], i // 4)
            else:
                g_w = key_words[i - 1]
            for j in range(4):
                tmp += (key_words[i - 4][j] ^ g_w[j]).to_bytes(1, sys.byteorder)
            key_words.append(tmp)

        keys = [reduce(add, key_words[i:i + 4]) for i in range(0, 11)]

        return keys

    @staticmethod
    def __g_fun(word, key_num):
        new_word = word[1:] + word[:1]
        result = b""
        for index, b in enumerate(new_word):
            result += (Encryption.S_table[b] ^ (Encryption.RC[key_num]
                                                if index == 0 else 0X00)).to_bytes(1, sys.byteorder)

        return result

    @staticmethod
    def __remove_PKCS_7_padding(x):
        remove_num = x[-1]
        return x[:-remove_num]
