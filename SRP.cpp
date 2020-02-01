#include "SRP.h"
#include "BigNum.h"

#include <string>
#include <algorithm>

#include <iostream>

#include <openssl/sha.h>
#include <openssl/evp.h>

SRPClient::SRPClient(){
    k.from_dec("3");
    a.from_hex("8266845392F83273477A763E6356B795737D49");

}

void SRPClient::step1(std::string username, std::string password,
                      BigNum B, BigNum g, BigNum N, BigNum s){
    
    unsigned char* result = new unsigned char[20];
    digest = EVP_MD_CTX_new();

    std::transform(username.begin(), username.end(), username.begin(), ::toupper);
    std::transform(password.begin(), password.end(), password.begin(), ::toupper);

    A = g.mod_exp(a, N);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, A.to_rev_bytearray(32), 32);
    EVP_DigestUpdate(digest, B.to_rev_bytearray(32), 32);

    EVP_DigestFinal(digest, result, NULL);
    std::reverse(result, result+20);

    BigNum u;
    u.from_bin(result, 20);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, username.c_str(), username.length());
    EVP_DigestUpdate(digest, ":", 1);
    EVP_DigestUpdate(digest, password.c_str(), password.length());

    EVP_DigestFinal(digest, result, NULL);
    std::reverse(result, result+20);

    BigNum p;
    p.from_bin(result, 20);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, s.to_rev_bytearray(32), 32);
    EVP_DigestUpdate(digest, p.to_bytearray(20), 20);
    
    EVP_DigestFinal(digest, result, NULL);
    std::reverse(result, result+20);

    BigNum x;
    x.from_bin(result, 20);

    S = (B - (g.mod_exp(x, N) * k)).mod_exp(a + (u * x), N);

    unsigned char* t = S.to_rev_bytearray(32);
    unsigned char* t1 = new unsigned char[16];
    unsigned char* t2 = new unsigned char[16];
    unsigned char* vK = new unsigned char[40];

    for(int i = 0; i < 16; ++i){
        t1[i] = t[i * 2];
        t2[i] = t[i * 2 + 1];
    }

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, t1, 16);

    EVP_DigestFinal(digest, result, NULL);

    for(int i = 0; i < 20; ++i){
        vK[i * 2] = result[i];
    }

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, t2, 16);

    EVP_DigestFinal(digest, result, NULL);

    for(int i = 0; i < 20; ++i){
        vK[i * 2 + 1] = result[i];
    }

    unsigned char* N_hash = new unsigned char[20];
    unsigned char* g_hash = new unsigned char[20];

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, N.to_rev_bytearray(32), 32);
    EVP_DigestFinal(digest, N_hash, NULL);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, g.to_rev_bytearray(1), 1);
    EVP_DigestFinal(digest, g_hash, NULL);

    for(int i = 0; i < 20; ++i){
        N_hash[i] = N_hash[i] ^ g_hash[i];
    }

    std::reverse(N_hash, N_hash+20);
    BigNum t3;
    t3.from_bin(N_hash, 20);

    std::reverse(vK, vK+40);
    BigNum K;
    K.from_bin(vK, 40);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, username.c_str(), username.length());

    EVP_DigestFinal(digest, result, NULL);
 
    std::reverse(result, result+20);
    BigNum t4;
    t4.from_bin(result, 20);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, t3.to_rev_bytearray(20), 20);
    EVP_DigestUpdate(digest, t4.to_rev_bytearray(20), 20);
    EVP_DigestUpdate(digest, s.to_rev_bytearray(32), 32);
    EVP_DigestUpdate(digest, A.to_rev_bytearray(32), 32);
    EVP_DigestUpdate(digest, B.to_rev_bytearray(32), 32);
    EVP_DigestUpdate(digest, K.to_rev_bytearray(40), 40);

    EVP_DigestFinal(digest, result, NULL);

    BigNum M;
    M.from_bin(result, 20);

    std::cout << "B=" << B.to_hex_string() << std::endl;
    std::cout << "g=" << g.to_hex_string() << std::endl;
    std::cout << "N=" << N.to_hex_string() << std::endl;
    std::cout << "s=" << s.to_hex_string() << std::endl;

    std::cout << "A=" << A.to_hex_string() << std::endl;
    std::cout << "u=" << u.to_hex_string() << std::endl;
    std::cout << "p=" << p.to_hex_string() << std::endl;
    std::cout << "x=" << x.to_hex_string() << std::endl;
    std::cout << "S=" << S.to_hex_string() << std::endl;

    std::cout << "t3=" << t3.to_hex_string() << std::endl;
    std::cout << "t4=" << t4.to_hex_string() << std::endl;
    std::cout << "K=" << K.to_hex_string() << std::endl;

    std::cout << "M=" << M.to_hex_string() << std::endl;
}