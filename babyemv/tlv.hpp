#ifndef __TLV__
#define __TLV__

#include "stdio.h"
#include "string.h"
#include <vector>
#include <span>
#include <unordered_set>
#include "tags.hpp"
#include <sstream>
#include <iomanip>
#include <format>

using namespace std;

const unordered_set<int> complexTags = { 0x6F, 0x61, 0xA5, 0x70, 0x71, 0x72, 0xBF0C, 0x77 };

class TLV {
  private:
    uint valuedBegin;

    TLV(span<uint8_t> _sbuff, uint vBegin) {
        for (auto& x : _sbuff)
            data.push_back(x);
        valuedBegin = vBegin;
    }

  public:
    vector<uint8_t> data;
    vector<TLV> tags;
    uint T;
    uint L;

    span<uint8_t> V() {
        return span<uint8_t>(data.begin() + valuedBegin, data.end());
    }

    uint size() {
        return data.size();
    }

    span<uint8_t> find(uint t) {
        if (T == t)
            return V();
            
        for (auto& tag : tags) {
            auto res = tag.find(t);
            if (res.size())
                return res;
        }
        return {};
    }

    static TLV parseTlv(span<uint8_t> buf, bool root = true) {
        int i = 0;
        int tg = buf[i];
        int l = 0;

        if ((buf[i++] & 0x1F) == 0x1F) {
            do {
                tg = (tg << 8) | buf[i];
            } while (buf[i++] & 0x80);
        }

        if (buf[i] & 0x80) {
            int k = buf[i++] ^ 0x80;
            while (k--) {
                l = (l << 8) | buf[i++];
            }
        } else {
            l = buf[i++];
        }
        TLV tlv(span(buf.begin(), buf.begin() + i + l), i);
        tlv.L = l;
        tlv.T = tg;

        if (complexTags.count(tlv.T)) {
            int len = 0;
            while (len < tlv.V().size()) {
                auto nestedTlv = parseTlv(tlv.V().subspan(len), false);
                tlv.tags.push_back(nestedTlv);
                len += nestedTlv.size();
            }
        }

        return tlv;
    }

    static vector<unsigned char> composeTlv(unsigned int t, unsigned int l, span<unsigned char> v) {
        vector<unsigned char> res;
        int i = 0;

        for (int k = 0; k < 4; k++) {
            unsigned char x = (t >> 8 * (3 - k) & 0x000000FF);
            if (x)
                res.push_back(x);
        }

        if (l <= 127) {
            res.push_back(l);
        } else {
            if (l <= 255) {
                res.push_back(0x81);
                res.push_back(l);
            } else {
                res.push_back(0x82);
                res.push_back(l >> 8);
                res.push_back(l);
            }
        }
        res.insert(res.end(), v.begin(), v.end());

        return res;
    }
};

static string vAsHexString(span<unsigned char> v) {
    stringstream ss;
    ss << hex << setfill('0') << uppercase;
    for_each(v.begin(), v.end(), [&](unsigned char x) { ss << setw(2) << static_cast<int>(x); });
    return ss.str();
}
// ├ ┌─ └ ─
static string tlvPrint(TLV& tlv, bool last = true, int padding = 0, uint m = 0, bool first = true) {
    string pipe = "├";
    if (last)
        pipe = "└";
    string beforeT = string(padding, ' ') + pipe + "─";
    int shift = 10 - beforeT.size() + 4;
    string beforeLV = string(shift, ' ');
    m = max(m, tlv.L * 2 + 15);
    shift = m - beforeT.size() - beforeLV.size() - tlv.L * 2;
    string beforeD = string(shift, ' ') + "|";
    auto header = "";
    if (first)
        header = "┌───────────────────────────────────────────────────\n";
    auto res = format("{}{}{:08X} {} {:03} {}{} {}\n", header, beforeT, tlv.T, beforeLV, tlv.L, vAsHexString(tlv.V()),
                      beforeD, tagsList[tlv.T]);

    for (auto& subTag : tlv.tags) {
        last = (&subTag == &tlv.tags.back());
        res += tlvPrint(subTag, last, padding + 2, m, false);
    }

    return res;
}
#endif