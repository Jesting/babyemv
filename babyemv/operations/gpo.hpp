#ifndef __GPO__
#define __GPO__
#include "operation.hpp"
#include "../settings.hpp"
#include "../structures/dol.hpp"
#include "../structures/aip.hpp"

class Gpo : public Operation {
  public:
    Gpo(TransactionObjects& _transactionObjects, Command* _command) : Operation(_transactionObjects, _command) {
    }

    void getAllData() {
        vector<unsigned int> tags = { 0x9F36, 0x9F13 };
        vector<unsigned char> data;

        for (auto& x : tags) {
            if (command->getData(x, data) == 0x9000) {
                auto t = TLV::parseTlv(data);
                transactionObjects.put(t);
                cout << tlvPrint(t) << endl;
            }
        }
    }

    ExecutionResult readRecordsGpo(vector<unsigned char>& staticData) {
        auto afl = transactionObjects.get(0x94);
        if (!afl) {
            cout << "AFL is empty, exiting" << endl;
            return ExecutionResult::Terminate;
        }
        
        if (afl->size() % 4) {
            cout << "AFL wrong size, exiting" << endl;
            return ExecutionResult::Terminate;
        }

        cout << "AFL is:";
        vectorPrint(*afl);

        int i = 0;
        int res = -1;

        while (i < afl->size()) {
            unsigned char sfi = afl->at(i++) >> 3;
            unsigned char recS = afl->at(i++);
            unsigned char recE = afl->at(i++);
            unsigned char numS = afl->at(i++);

            vector<unsigned char> responseData;

            cout << "Sfi " << static_cast<int>(sfi) << " records from " << static_cast<int>(recS) << " to " << static_cast<int>(recE) << endl;

            for (; recS <= recE; recS++) {
                cout << "About to read sfi " << static_cast<int>(sfi) << " record " << static_cast<int>(recS) << endl;
                unsigned int len = 255;
                res = command->readRecord(sfi, recS, responseData);

                if (res != 0x9000){
                    return ExecutionResult::Terminate;
                }
                    

                int iLen = len;
                auto tlv = TLV::parseTlv(responseData);
                cout << tlvPrint(tlv) << endl;

                transactionObjects.put(tlv);

                if (numS) {
                    numS--;
                    if (sfi <= 10) {
                        staticData.insert(staticData.end(), tlv.V().begin(), tlv.V().end());
                    } else {
                        for (int i = 0; i < iLen; i++) {
                            staticData.push_back(responseData[i]);
                        }
                    }
                }
            }
        }

        auto tag9F4A = transactionObjects.get(0x9F4A);

        if (tag9F4A && tag9F4A->size() == 1) {
            if ((*tag9F4A)[0] == 0x82) {
                cout << "Adding AIP to the static data" << endl;
                auto tag82 = transactionObjects.get(0x82);
                if (tag82) {
                    staticData.insert(staticData.end(), tag82->begin(), tag82->end());
                } else {
                    cout <<"AIP not found" <<endl;
                    return ExecutionResult::Terminate;
                }
            }
        }

        return ExecutionResult::Success;
    }

    ExecutionResult getProcessingOptions() {
        auto pdol = transactionObjects.get<DOL>(0x9f38);

        vector<uint8_t> tag83;
        if (pdol) {
            tag83 = pdol->build();
        }

        vector<unsigned char> tag83TL = { 0x83 };
        tlvLengthToVector(tag83.size(), tag83TL);
        tag83.insert(tag83.begin(), tag83TL.begin(), tag83TL.end());
        vector<unsigned char> responseData;
        unsigned int len = 255;
        int res = command->gpo(tag83, responseData);

        if (res == 0x9000) {
            cout << "GPO Success" << endl;
        } else {
            if (res == 0x6985)
                return ExecutionResult::Denied;
            else
                return ExecutionResult::Terminate;
        }

        auto tlv = TLV::parseTlv(responseData);

        cout << tlvPrint(tlv) << endl;

        transactionObjects.put(tlv);

        vector<unsigned char> staticData;
        auto readRecordsRes = readRecordsGpo(staticData);

        vectorPrint(staticData);
        transactionObjects.put(0x95, { 0, 0, 0, 0, 0 });
        
        transactionObjects.get<AIP>(0x82)->toStream(cout);

        return readRecordsRes;
    }

    ExecutionResult execute() override{
        cout << "***********************" << endl;
        cout << "[GET PROCESSING OPTIONS]" << endl;
        cout << "***********************" << endl;
        return getProcessingOptions();
    }

    ~Gpo() override {};
};

#endif