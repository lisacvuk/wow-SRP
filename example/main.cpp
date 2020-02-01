#include "wow_srp/SRP.h"

int main(){
    WOW_SRP::SRPClient client;

    WOW_SRP::BigNum B("31396E76E6BC4C2BAF836FC8437162FEFC14DD57107B3537D25015818ABB12D");
    WOW_SRP::BigNum N("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    WOW_SRP::BigNum s("F3BDF38231BD4FC33D36086CB7F27246511038C0FB6C53260560E58A91EDE97B");

    WOW_SRP::BigNum g;
    g.from_dec("7");

    client.step1("test", "test", B, g, N, s);

    return 0;
}