#ifndef __DOL__
#define __DOL__
#include "../kernel.hpp"
#include "../tags.hpp"

using namespace std;
class DOL : public TransactionObjectEx {
    vector<pair<uint, int>> tags;
    int totaLength = 0;

  public:
    DOL(vector<unsigned char>& _value, TransactionObjects& _transactionObjects)
      : TransactionObjectEx(_value,_transactionObjects){
        int i = 0;

        while (i < _value.size()) {
            int t = _value[i];
            int l = 0;

            if ((_value[i++] & 0x1F) == 0x1F) {
                do {
                    t = (t << 8) | _value[i];
                } while (_value[i++] & 0x80);
            }

            if (_value[i] & 0x80) {
                int k = _value[i++] ^ 0x80;
                while (k--) {
                    l = (l << 8) | _value[i++];
                }
            } else {
                l = _value[i++];
            }

            totaLength += l;
            tags.push_back(pair(t, l));
        }
    }
    vector<pair<uint, int>>& getTags () {
        return tags;
    }

    vector<uint8_t> build() {
        vector<uint8_t> res;
        cout << "Composing DOL:" << endl;

        auto maxLen = max_element(tags.begin(), tags.end(), [](const pair<uint, int>& a, const pair<uint, int>& b) {
            return a.second < b.second;
        })->second * 2;
        
        for (auto& tag : tags) {
            auto dolTag = transactionObjects.get(tag.first);
            
            if (dolTag) {
                if (dolTag->size() != tag.second) {
                    throw runtime_error(format("TAG 0x{:X} size problem, expected {} , got {}", tag.first,tag.second, dolTag->size()));
                    
                }else{
                    cout << hex << setw(4) << setfill(' ') << right << tag.first << " ";
                    vectorPrint(*dolTag, cout, false);
                    cout << setw(maxLen-tag.second*2)<<right<<setfill(' ')<<"| "<<tagsList[tag.first] << endl;
                    res.insert(res.end(), dolTag->begin(), dolTag->end());
                }
            } else {
                for (int i = 0; i < tag.second; i++) {
                    res.push_back(0x00);
                }
            }
        }
        return res;
    }
};

#endif