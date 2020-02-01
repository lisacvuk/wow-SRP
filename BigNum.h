#pragma once

#include <openssl/bn.h>

namespace WOW_SRP{
    class BigNum{
    public:
        BigNum();
        BigNum(const char* data);

        BigNum from_hex(const char* data);
        BigNum from_dec(const char* data);
        BigNum from_bin(const unsigned char* data, int length);

        unsigned char* to_rev_bytearray(int length);
        unsigned char* to_bytearray(int length);

        char* to_hex_string();

        BigNum operator+(const BigNum& b);
        BigNum operator-(const BigNum& b);
        BigNum operator*(const BigNum& b);
        BigNum operator/(const BigNum& b);

        BigNum operator=(const BigNum& b);

        BigNum exp(const BigNum& b);
        BigNum mod_exp(const BigNum& b, const BigNum& d);

        BIGNUM* bn;
    private:
    };
}