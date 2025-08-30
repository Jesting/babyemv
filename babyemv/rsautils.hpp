#ifndef __RSAUTULS__
#define __RSAUTULS__
#include <openssl/bn.h>
#include <vector>
#include "boost/multiprecision/cpp_int.hpp"

using namespace std;

vector<unsigned char> sha1(const vector<unsigned char>& v){
    auto leftrot = [](uint32_t x, uint32_t n){ return (x<<n) | (x>>(32-n)); };

    // Initialize variables
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // Pre-processing (padding)
    vector<unsigned char> msg(v);
    uint64_t bit_len = (uint64_t)msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() % 64) != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<unsigned char>((bit_len >> (i*8)) & 0xFF));

    // Process chunks
    for (size_t offset = 0; offset < msg.size(); offset += 64){
        uint32_t w[80];
        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; ++i){
            size_t idx = offset + i*4;
            w[i] = (uint32_t(msg[idx]) << 24) |
                   (uint32_t(msg[idx+1]) << 16) |
                   (uint32_t(msg[idx+2]) << 8) |
                   (uint32_t(msg[idx+3]));
        }
        // Extend to 80 words
        for (int i = 16; i < 80; ++i)
            w[i] = leftrot(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        for (int i = 0; i < 80; ++i){
            uint32_t f, k;
            if (i < 20){ f = (b & c) | ((~b) & d); k = 0x5A827999; }
            else if (i < 40){ f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60){ f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t temp = leftrot(a,5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftrot(b,30);
            b = a;
            a = temp;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    vector<unsigned char> res(20);
    uint32_t hs[5] = {h0,h1,h2,h3,h4};
    for (int i = 0; i < 5; ++i){
        res[i*4+0] = (hs[i] >> 24) & 0xFF;
        res[i*4+1] = (hs[i] >> 16) & 0xFF;
        res[i*4+2] = (hs[i] >> 8)  & 0xFF;
        res[i*4+3] = (hs[i])       & 0xFF;
    }
    return res;
}



vector<uint8_t> rsa_recover(const vector<uint8_t>& data,
                            const vector<uint8_t>& ca_modulus) {
    using boost::multiprecision::cpp_int;

    auto to_cpp_int = [](const vector<uint8_t>& bytes) {
        cpp_int v = 0;
        for (uint8_t b : bytes) {
            v <<= 8;
            v |= cpp_int(b);
        }
        return v;
    };

    if (ca_modulus.empty()) return {};

    cpp_int base = to_cpp_int(data);
    cpp_int mod  = to_cpp_int(ca_modulus);
    cpp_int exp  = 3;

    if (mod == 0) return {};

    cpp_int result = boost::multiprecision::powm(base, exp, mod);

    // Convert result to big-endian bytes (no leading zero padding, like BN_bn2bin)
    vector<uint8_t> out;
    if (result == 0) {
        out.push_back(0);
        return out;
    }
    while (result > 0) {
        uint8_t byte = static_cast<uint8_t>(result & 0xFF);
        out.push_back(byte);
        result >>= 8;
    }
    reverse(out.begin(), out.end());
    return out;
}



#endif