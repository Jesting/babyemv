#ifndef __RSAUTULS__
#define __RSAUTULS__
#include <openssl/bn.h>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace std;

vector<unsigned char> sha1(const vector<unsigned char>& v){
    unsigned char md[20];
    SHA1(v.data(), v.size(), md);
    vector<unsigned char> res;
    res.assign(md,md+20);
    return res;
}

vector<uint8_t> rsa_recover(const vector<uint8_t>& data,
                                         const vector<uint8_t>& ca_modulus) {
    BIGNUM *base = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *exp = BN_new();
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    // Convert input to BIGNUM
    BN_bin2bn(data.data(), data.size(), base);
    BN_bin2bn(ca_modulus.data(), ca_modulus.size(), mod);
    BN_set_word(exp, 3);  // Public exponent is 3
    
    // Perform modular exponentiation
    BN_mod_exp(result, base, exp, mod, ctx);
    
    // Convert result back to bytes
    vector<uint8_t> recovered(BN_num_bytes(result));
    BN_bn2bin(result, recovered.data());
    
    // Cleanup
    BN_free(base);
    BN_free(mod);
    BN_free(exp);
    BN_free(result);
    BN_CTX_free(ctx);
    
    return recovered;
}

#endif