#ifndef __SETTINGS1__
#define __SETTINGS1__
#include <vector>
#include <unordered_map>
#include <string>
#include <utility>
#include "utils.hpp"
#include "structures/certs.hpp"
using namespace std;

const unsigned int TAC_ONLINE = 0xFFFFFF01;
const unsigned int TAC_DEFAULT = 0xFFFFFF02;
const unsigned int TAC_DENIAL = 0xFFFFFF03;
const unsigned int FLOOR_LIMIT = 0xFFFFFF04;

class Setttings {
  public:
    virtual vector<vector<uint8_t>>& getAids() = 0;
    virtual vector<pair<uint32_t, vector<uint8_t>>>& getSettings() = 0;
    virtual CAPK& getCapk(vector<uint8_t> rid, uint8_t idx) = 0;
};

class SampleSettings : public Setttings {
    unsigned long long rid_idx2Long(vector<uint8_t>& rid, uint8_t idx) {
        unsigned long long res = 0;

        for (int i = 0; i < 5; i++) {
            res = res << 8;
            res |= rid[i];
        }

        res <<= 8;
        res |= idx;

        return res;
    }
    vector<vector<uint8_t>> aids = { { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 },
                                     { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 } };

    vector<pair<uint32_t, vector<uint8_t>>> settings = {
        { 0x9F09, { 0x00, 0x02 } },  // AVN
        { 0x9F35, { 0x22 } },        // Terminal type
        { 0x9F1A, { 0x09, 0x81 } },  // Terminal country code
        //{ 0x9F33, { 0x20, 0x80, 0xc8 } },// terminal capabilities with offline plain pin
        { 0x9F33, { 0x20, 0x00, 0xc8 } },              // terminal capabilities no cvms 
        { 0x9F40, { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },  // additional terminal capabilities

        { TAC_DENIAL, { 0x00, 0x10, 0x00, 0x00, 0x00 } },
        { TAC_ONLINE, { 0xDC, 0x40, 0x04, 0xF8, 0x00 } },
        { TAC_DEFAULT, { 0xFF, 0xFF, 0xFF, 0xFF, 0x00 } },
        { FLOOR_LIMIT, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },

    };
    unordered_map<unsigned long long, CAPK> capks = {
        { 0xA00000000405,
          CAPK{
              { 0xA0, 0x00, 0x00, 0x00, 0x04 },
              0x05,
              plainArrOfHexToVector(string("B8048ABC30C90D976336543E3FD7091C8FE4800DF820ED55E7E94813ED00555B573FECA3D84"
                                           "AF6131A"
                                           "651D66CFF4284FB13B635EDD0EE40176D8BF04B7FD1C7BACF9AC7327DFAA8AA72D10DB3B8E7"
                                           "0B2DDD8"
                                           "11CB4196525EA386ACC33C0D9D4575916469C4E4F53E8E1C912CC618CB22DDE7C3568E90022"
                                           "E6BBA77"
                                           "0202E4522A2DD623D180E215BD1D1507FE3DC90CA310D27B3EFCCD8F83DE3052CAD1E48938C"
                                           "68D095A"
                                           "AC91B5F37E28BB49EC7ED597")),
              { 0x03 },
              { 0x24, 0x12, 0x31 },
              { 0xEB, 0xFA, 0x0D, 0x5D, 0x06, 0xD8, 0xCE, 0x70, 0x2D, 0xA3,
                0xEA, 0xE8, 0x90, 0x70, 0x1D, 0x45, 0xE2, 0x74, 0xC8, 0x45 },
          } },
        { 0xA00000000406,  // 0x06 IDX
          CAPK{
              { 0xA0, 0x00, 0x00, 0x00, 0x04 },
              0x05,
              plainArrOfHexToVector(string("CB26FC830B43785B2BCE37C81ED334622F9622F4C89AAE641046B2353433883F307FB7C9741"
                                           "62DA72F7A4EC75D9D657336865B8D3023D3D645667625C9A07A6B7A137CF0C64198AE38FC23"
                                           "8006FB2603F41F4F3BB9DA1347270F2F5D8C606E420958C5F7D50A71DE30142F70DE468889B"
                                           "5E3A08695B938A50FC980393A9CBCE44AD2D64F630BB33AD3F5F5FD495D31F37818C1D94071"
                                           "342E07F1BEC2194F6035BA5DED3936500EB82DFDA6E8AFB655B1EF3D0D7EBF86B66DD9F29F6"
                                           "B1D324FE8B26CE38AB2013DD13F611E7A594D675C4432350EA244CC34F3873CBA06592987A1"
                                           "D7E852ADC22EF5A2EE28132031E48F74037E3B34AB747F")),
              { 0x03 },
              { 0x24, 0x12, 0x31 },
              { 0xEB, 0xFA, 0x0D, 0x5D, 0x06, 0xD8, 0xCE, 0x70, 0x2D, 0xA3,
                0xEA, 0xE8, 0x90, 0x70, 0x1D, 0x45, 0xE2, 0x74, 0xC8, 0x45 },
          } },
        { 0xA00000000309,  // 0x06 IDX
          CAPK{
              { 0xA0, 0x00, 0x00, 0x00, 0x03 },
              0x09,
              plainArrOfHexToVector(string("9D912248DE0A4E39C1A7DDE3F6D2588992C1A4095AFBD1824D1BA74847F2BC4926D2EFD904B"
                                           "4B54954CD189A54C5D1179654F8F9B0D2AB5F0357EB642FEDA95D3912C6576945FAB897E706"
                                           "2CAA44A4AA06B8FE6E3DBA18AF6AE3738E30429EE9BE03427C9D64F695FA8CAB4BFE376853E"
                                           "A34AD1D76BFCAD15908C077FFE6DC5521ECEF5D278A96E26F57359FFAEDA19434B937F1AD99"
                                           "9DC5C41EB11935B44C18100E857F431A4A5A6BB65114F174C2D7B59FDF237D6BB1DD0916E64"
                                           "4D709DED56481477C75D95CDD68254615F7740EC07F330AC5D67BCD75BF23D28A140826C026"
                                           "DBDE971A37CD3EF9B8DF644AC385010501EFC6509D7A41")),
              { 0x03 },
              { 0x24, 0x12, 0x31 },
              { 0x1F, 0xF8, 0x0A, 0x40, 0x17, 0x3F, 0x52, 0xD7, 0xD2, 0x7E,
                0x0F, 0x26, 0xA1, 0x46, 0xA1, 0xC8, 0xCC, 0xB2, 0x90, 0x46 },
          } }

    };

  public:
    vector<vector<uint8_t>>& getAids() override {
        return aids;
    }
    vector<pair<uint32_t, vector<uint8_t>>>& getSettings() override {
        return settings;
    }
    CAPK& getCapk(vector<uint8_t> rid, uint8_t idx) override {
        auto key = rid_idx2Long(rid, idx);

        if (capks.count(key))
            return capks[key];
        else
            throw runtime_error("capk not found, err!");
    }
};

#endif