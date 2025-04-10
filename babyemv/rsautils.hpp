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
                                  
    unique_ptr<BIGNUM, decltype(&BN_free)> base(BN_new(), BN_free);
    unique_ptr<BIGNUM, decltype(&BN_free)> mod(BN_new(), BN_free);
    unique_ptr<BIGNUM, decltype(&BN_free)> exp(BN_new(), BN_free);
    unique_ptr<BIGNUM, decltype(&BN_free)> result(BN_new(), BN_free);
    unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctx(BN_CTX_new(), BN_CTX_free);
    
    // Convert input to BIGNUM
    BN_bin2bn(data.data(), data.size(), base.get());
    BN_bin2bn(ca_modulus.data(), ca_modulus.size(), mod.get());
    BN_set_word(exp.get(), 3);  // Public exponent is 3
    
    // Perform modular exponentiation
    BN_mod_exp(result.get(), base.get(), exp.get(), mod.get(), ctx.get());
    
    // Convert result back to bytes
    vector<uint8_t> recovered(BN_num_bytes(result.get()));
    BN_bn2bin(result.get(), recovered.data());
    
    return recovered;
}

#endif