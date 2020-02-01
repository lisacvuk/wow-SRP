#include "BigNum.h"

#include <algorithm>

#include <openssl/bn.h>

using namespace WOW_SRP;

BigNum::BigNum(){
    bn = BN_new();
}

BigNum::BigNum(const char* data){
    bn = BN_new();

    from_hex(data);
}

BigNum BigNum::from_hex(const char* data){
    BN_hex2bn(&bn, data);
    
    return *this;
}

BigNum BigNum::from_dec(const char* data){
    BN_dec2bn(&bn, data);

    return *this;
}

BigNum BigNum::from_bin(const unsigned char* data, int length){
    BN_bin2bn(data, length, bn);

    return *this;
}

unsigned char* BigNum::to_rev_bytearray(int length){
    unsigned char* temp;
    temp = new unsigned char[length];

    BN_bn2bin(bn, temp);

    std::reverse(temp, temp+length);

    return temp;
}

unsigned char* BigNum::to_bytearray(int length){
    unsigned char* temp;
    temp = new unsigned char[length];

    BN_bn2bin(bn, temp);

    return temp;
}

char* BigNum::to_hex_string(){
    char* temp;
    temp = BN_bn2hex(bn);

    return temp;
}

BigNum BigNum::operator+(const BigNum& b){
    BigNum temp;

    BN_add(temp.bn, bn, b.bn);

    return temp;
}

BigNum BigNum::operator-(const BigNum& b){
    BigNum temp;

    BN_sub(temp.bn, bn, b.bn);

    return temp;
}

BigNum BigNum::operator*(const BigNum& b){
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_mul(temp.bn, bn, b.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

BigNum BigNum::operator/(const BigNum& b){
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_div(temp.bn, nullptr, bn, b.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

BigNum BigNum::operator=(const BigNum& b){
    bn = b.bn;

    return *this;
}

BigNum BigNum::exp(const BigNum& b){
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_exp(temp.bn, bn, b.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}

BigNum BigNum::mod_exp(const BigNum &b, const BigNum &c){
    BigNum temp;

    BN_CTX* temp_ctx = BN_CTX_new();
    BN_mod_exp(temp.bn, bn, b.bn, c.bn, temp_ctx);
    BN_CTX_free(temp_ctx);

    return temp;
}