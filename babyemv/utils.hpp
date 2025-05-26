#ifndef __UTILS__
#define __UTILS__
#include <stdio.h>
#include "tlv.hpp"
#include <vector>
#include <iostream>
#include <sstream>
#include <format>
#include <string>

using namespace std;

template <typename Container>
string bytesAsHexString(const Container& container) {
    std::stringstream result;
    for (const auto& v : container) {
        result << setfill('0') << setw(sizeof(v) * 2) << hex << +v;
    }
    return result.str();
}

void pointerPrint(unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        cout << uppercase << setfill('0') << right << setw(2) << hex << static_cast<int>(data[i]);
    }
    cout << endl;
}

void tlvLengthToVector(unsigned int l, vector<unsigned char>& v) {
    if (l <= 127) {
        v.push_back(l);
    } else {
        if (l <= 255) {
            v.push_back(0x81);
            v.push_back(l);
        } else {
            v.push_back(0x82);
            v.push_back(l >> 8);
            v.push_back(l);
        }
    }
}

template <typename Container>
void vectorPrint(const Container& v, ostream& ss = cout, bool newLine = true) {
    for (const auto& x : v) {
        ss << "" << uppercase << setfill('0') << setw(2) << hex<< right << static_cast<int>(x);
    }
    if(newLine)
        ss << endl;
}


void longToBCDVectorOfKnownSize(unsigned long l, vector<unsigned char>& res) {
    auto t = l;
    int e = 1;
    int v = res.size() - 1;
    while (v >= 0) {
        res[v] = t % 10;
        t = t / 10;
        res[v] = res[v] | (t % 10 << 4);
        t = t / 10;
        v--;
    }
}

vector<uint8_t> longToBCDVectorOfKnownSize(unsigned long l,uint8_t size) {
    vector<unsigned char> res(size);
    auto t = l;
    int e = 1;
    int v = res.size() - 1;
    while (v >= 0) {
        res[v] = t % 10;
        t = t / 10;
        res[v] = res[v] | (t % 10 << 4);
        t = t / 10;
        v--;
    }
    return res;
}


vector<unsigned char> longToVector(unsigned long l) {
    vector<unsigned char> res;
    auto t = l;
    int e = 1;
    while (t) {
        res.insert(res.begin(), t % 10);
        t = t / 10;
    }
    return res;
}

long long bcdToLong(const vector<unsigned char>& numv) {
    long res = 0x00;
    for (auto x : numv) {
        res *= 10;
        res += ((x >> 4) & 0x0F);
        res *= 10;
        res += x & 0x0F;
    }
    return res;
}

void plainArrOfHexToVector(string& s, vector<unsigned char>& v) {
    if (s.size() % 2)
        throw runtime_error("wrong size");

    for (int i = 0; i < s.size(); i += 2) {
        std::string byteString = s.substr(i, 2);
        unsigned char c = strtol(byteString.c_str(), NULL, 16);
        v.push_back(c);
    }
    vectorPrint(v);
}

vector<unsigned char>constexpr plainArrOfHexToVector(const string& s){
    vector<unsigned char> v;
    if (s.size() % 2)
        throw runtime_error("wrong size");

    for (int i = 0; i < s.size(); i += 2) {
        std::string byteString = s.substr(i, 2);
        unsigned char c = strtol(byteString.c_str(), NULL, 16);
        v.push_back(c);
    }
    return v;
}

TLV plainnArrOfHexToTLV(string s) {
    auto v = plainArrOfHexToVector(s);
    return TLV::parseTlv(v);
}

void toStreamUniversal(ostream& ss, const string& caption, const vector<vector<string>>& captions, const vector<uint8_t>& value) {
    ss << "┌─" << caption << "──────────────────────────────────────────────────────────" << endl;

    // Find the maximum caption length for alignment
    size_t maxCaptionLength = 0;
    for (const auto& byteCaptions : captions) {
        for (const auto& bitCaption : byteCaptions) {
            if (!bitCaption.empty()) {
                maxCaptionLength = max(maxCaptionLength, bitCaption.size());
            }
        }
    }

    for (size_t byteIndex = 0; byteIndex < captions.size(); ++byteIndex) {
        ss << "├─ Byte " << (byteIndex + 1) << ": " << endl;
        for (size_t bitIndex = 0; bitIndex < captions[byteIndex].size(); ++bitIndex) {
            if (!captions[byteIndex][bitIndex].empty()) {
                ss << "│   ├─ " << setw(maxCaptionLength) << setfill(' ') << left << captions[byteIndex][bitIndex] << " : "
                   << (value[byteIndex] & (0x80 >> bitIndex) ? "true" : "false") << endl;
            }
        }
    }
}


#endif