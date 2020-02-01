#include <iostream>
#include <string>
#include <sstream>
#include <memory>
#include <iomanip>
#include <algorithm>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

using std::string;

int main(){
    // Results --
    BIGNUM* A;
    A = BN_new();
    
    BIGNUM* x;
    x = BN_new();
    
    BIGNUM* M;
    M = BN_new();
    
    BIGNUM* S;
    S = BN_new();    
    
    BIGNUM* K;
    K = BN_new();

    // Inputs --
    string account = "TEST";
    string password = "TEST";

    string user = "TEST:TEST";

    BIGNUM* k;
    k = BN_new();
    BN_dec2bn(&k, "3");

    BIGNUM* B;
    B = BN_new();
    BN_hex2bn(&B, "31396E76E6BC4C2BAF836FC8437162FEFC14DD57107B3537D25015818ABB12D");

    BIGNUM* g;
    g = BN_new();
    BN_dec2bn(&g, "7");

    BIGNUM* N;
    N = BN_new();
    BN_hex2bn(&N, "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");

    BIGNUM* s;
    s = BN_new();
    BN_hex2bn(&s, "F3BDF38231BD4FC33D36086CB7F27246511038C0FB6C53260560E58A91EDE97B");
    
    BIGNUM* a;
    a = BN_new();
    BN_hex2bn(&a, "8266845392F83273477A763E6356B795737D49");

    BN_CTX* temp;
    temp = BN_CTX_new();

    BN_mod_exp(A, g, a, N, temp);
    std::cout << "A=" << BN_bn2hex(A) << std::endl;
    std::cout << "B=" << BN_bn2hex(B) << std::endl;

    EVP_MD_CTX* digest;
    digest = EVP_MD_CTX_new();
    EVP_DigestInit(digest, EVP_sha1());

    unsigned char* A_data;
    A_data = new unsigned char[32];
    BN_bn2bin(A, A_data);
    std::reverse(A_data, A_data+32);

    unsigned char* B_data;
    B_data = new unsigned char[32];
    BN_bn2bin(B, B_data);
    std::reverse(B_data, B_data+32);

    EVP_DigestUpdate(digest, A_data, 32);
    EVP_DigestUpdate(digest, B_data, 32);

    unsigned char result[20];

    EVP_DigestFinal(digest, result, NULL);
    std::reverse(result, result+20);

    BIGNUM* u;
    u = BN_new();
    BN_bin2bn(result, 20, u);

    std::cout << "u=" << BN_bn2hex(u) << std::endl;

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, user.c_str(), user.length());
    EVP_DigestFinal(digest, result, NULL);

    BIGNUM* p;
    p = BN_new();
    BN_bin2bn(result, 20, p);
    std::cout << "p=" << BN_bn2hex(p) << std::endl;

    EVP_DigestInit(digest, EVP_sha1());

    unsigned char* s_data;
    s_data = new unsigned char[32];
    BN_bn2bin(s, s_data);
    std::reverse(s_data, s_data+32);

    unsigned char* p_data;
    p_data = new unsigned char[20];
    BN_bn2bin(p, p_data);
    std::reverse(p_data, p_data+20);

    EVP_DigestUpdate(digest, s_data, 32);
    EVP_DigestUpdate(digest, p_data, 20);

    EVP_DigestFinal(digest, result, NULL);
    std::reverse(result, result+20);

    BN_bin2bn(result, 20, x);

    std::cout << "x=" << BN_bn2hex(x) << std::endl;

    //
    // HERE STARTS S
    //

    BIGNUM* gmodpowxN;
    gmodpowxN = BN_new();
    BN_mod_exp(gmodpowxN, g, x, N, temp);

    BIGNUM* gmodpowxNmulk;
    gmodpowxNmulk = BN_new();
    BN_mul(gmodpowxNmulk, gmodpowxN, k, temp);

    BIGNUM* Bminusabove;
    Bminusabove = BN_new();
    BN_sub(Bminusabove, B, gmodpowxNmulk);

    BIGNUM* umulx;
    umulx = BN_new();
    BN_mul(umulx, u, x, temp);

    BIGNUM* umulxplusa;
    umulxplusa = BN_new();
    BN_add(umulxplusa, a, umulx);

    BN_mod_exp(S, Bminusabove, umulxplusa, N, temp);

    std::cout << "S=" << BN_bn2hex(S) << std::endl;

    //
    // HERE ENDS S YEEET
    //

    unsigned char* t;
    t = new unsigned char[32];
    BN_bn2bin(S, t);

    std::reverse(t, t+32);

    unsigned char* t1;
    t1 = new unsigned char[16];

    unsigned char* t2;
    t2 = new unsigned char[16];

    unsigned char* vK;
    vK = new unsigned char[40];

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

    unsigned char* hash;
    hash = new unsigned char[20];

    unsigned char* N_data;
    N_data = new unsigned char[32];

    unsigned char* g_data;
    g_data = new unsigned char[1];

    BN_bn2bin(N, N_data);
    BN_bn2bin(g, g_data);

    std::reverse(N_data, N_data+32);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, N_data, 32);

    EVP_DigestFinal(digest, hash, NULL);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, g_data, 1);
    
    EVP_DigestFinal(digest, result, NULL);

    for(int i = 0; i < 20; ++i){
        hash[i] = hash[i] ^ result[i];
    }

    std::reverse(hash, hash+20);

    BIGNUM* t3;
    t3 = BN_new();
    BN_bin2bn(hash, 20, t3);

    std::reverse(vK, vK+40);

    BN_bin2bn(vK, 40, K);

    EVP_DigestInit(digest, EVP_sha1());
    EVP_DigestUpdate(digest, account.c_str(), account.length());

    EVP_DigestFinal(digest, result, NULL);

    std::reverse(result, result+20);

    BIGNUM* t4_correct;
    t4_correct = BN_new();
    BN_bin2bn(result, 20, t4_correct);

    EVP_DigestInit(digest, EVP_sha1());

    unsigned char* t3_data;
    t3_data = new unsigned char[20];

    unsigned char* t4_data;
    t4_data = new unsigned char[20];

    BN_bn2bin(t3, t3_data);
    BN_bn2bin(t4_correct, t4_data);

    std::cout << "t3=" << BN_bn2hex(t3) << std::endl;
    std::cout << "t4_correct=" << BN_bn2hex(t4_correct) << std::endl;
    std::cout << "K=" << BN_bn2hex(K) << std::endl;

    std::reverse(t3_data, t3_data+20);
    std::reverse(t4_data, t4_data+20);
    std::reverse(vK, vK+40);

    EVP_DigestUpdate(digest, t3_data, 20);
    EVP_DigestUpdate(digest, t4_data, 20);
    EVP_DigestUpdate(digest, s_data, 32);
    EVP_DigestUpdate(digest, A_data, 32);
    EVP_DigestUpdate(digest, B_data, 32);
    EVP_DigestUpdate(digest, vK, 40);

    EVP_DigestFinal(digest, result, NULL);

    BN_bin2bn(result, 20, M);

    std::cout << "M=" << BN_bn2hex(M) << std::endl;
    return 0;
}