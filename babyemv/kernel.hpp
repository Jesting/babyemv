#ifndef __BABYEMV__
#define __BABYEMV__

#include <unordered_map>
#include "transactionobject.hpp"
#include "settings.hpp"
#include "command.hpp"

#include "structures/dol.hpp"
#include "settings.hpp"
#include "operations/selection.hpp"
#include "operations/gpo.hpp"
#include "operations/restrictions.hpp"
#include "operations/crypto.hpp"
#include "operations/oda.hpp"
#include "operations/cardholder.hpp"
#include "operations/ac1.hpp"
#include "operations/ac2.hpp"
#include "operations/trm.hpp"
#include "reader.hpp"

using namespace std;
using SelectionCallback = function<int(vector<string>&)>;
using PinEntryCallback = function<vector<uint8_t>()>;
using OnlineRequestCallback =
    function<void(const unordered_map<uint32_t, vector<uint8_t>>&, vector<pair<uint8_t, vector<uint8_t>>>&)>;

class Kernel {
  private:
    Setttings& settings;
    Command command;
    SelectionCallback& selectionCallback;
    PinEntryCallback& pinEntryCallback;
    OnlineRequestCallback& onlineRequestCallback;

    void online(TransactionObjects& to) {
        vector<pair<uint8_t, vector<uint8_t>>> response;
        onlineRequestCallback(to.getMap(), response);
        for (auto i : response) {
            to.put(i.first, i.second);
        }
    }

    void init(TransactionObjects& to, uint64_t amount, uint64_t amountOther, uint8_t transactionType,
              uint32_t transactionDate, uint16_t transactionCurrency) {
        to.put(0x9F02, longToBCDVectorOfKnownSize(amount, 6));
        to.put(0x9F03, longToBCDVectorOfKnownSize(amountOther, 6));
        to.put(0x9C, { transactionType });
        to.put(0x9A, longToBCDVectorOfKnownSize(transactionDate, 3));
        to.put(0x5F2A, longToBCDVectorOfKnownSize(transactionCurrency, 2));
        to.put(0x9F21, { 0x20, 0x19, 0x22 });
        to.put(0x9B, { 0x00, 0x00 });
    }

  public:
    Kernel(Setttings& _settings, Reader& _reader, SelectionCallback& _selectionCallback,
           PinEntryCallback& _pinEntryCallback, OnlineRequestCallback& _onlineRequestCallback)
      : settings(_settings)
      , command(_reader)
      , selectionCallback(_selectionCallback)
      , pinEntryCallback(_pinEntryCallback)
      , onlineRequestCallback(_onlineRequestCallback) {
    }
    bool peformOperation(uint64_t amount, uint64_t amountOther, uint8_t transactionType, uint32_t transactionDate,
                         uint16_t transactionCurrency) {
        TransactionObjects to;

        init(to, amount, amountOther, transactionType, transactionDate, transactionCurrency);

        Selection selection(to, &command, settings, selectionCallback);
        Gpo gpo(to, &command);
        Restrictions rst(to);
        Crypto cry(to, &command, settings);
        Oda oda(to, &command, cry);
        Cardholder ch(to, &command, cry, pinEntryCallback);
        TRM trm(to);
        AC1 ac1(to, &command, oda, cry);
        AC2 ac2(to, &command, oda, cry);

        vector<Operation*> operations = { &selection, &gpo, &rst, &cry, &oda, &trm, &ch, &ac1, &ac2 };

        for (auto& op : operations) {
            auto res = op->execute();
            switch (res) {
                case ExecutionResult::Success: {
                    cout << "Success" << endl;
                    break;
                }
                case ExecutionResult::Approved: {
                    cout << "Approve" << endl;
                    return true;
                }
                case ExecutionResult::Denied: {
                    cout << "Deny" << endl;
                    return false;
                }

                case ExecutionResult::Online: {
                    cout << "Online" << endl;
                    online(to);
                    break;
                }
                
                case ExecutionResult::OnlineButCdaFailed: {
                    cout << "Online but CDA failed" << endl;
                    break;
                }

                case ExecutionResult::Terminate: {
                    cout << "Terminate" << endl;
                    return false;
                }
                default: {
                    cout << "Unknown result" << endl;
                    return false;
                }
            }
        }

        return false;
    }

    ~Kernel() {
    }
};
#endif