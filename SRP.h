#pragma once

#include "BigNum.h"

#include <string>

#include <openssl/evp.h>

class SRPClient{
public:
    SRPClient();

    void step1(std::string username, std::string password,
               BigNum B, BigNum g, BigNum N, BigNum s);
    
private:
    BigNum k, a, A, x, M, S, K;

    EVP_MD_CTX* digest;
};