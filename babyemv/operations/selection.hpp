#ifndef __SELECTION__
#define __SELECTION__
#include "operation.hpp"
#include "../settings.hpp"

class Selection : public Operation {
  private:
    Setttings& settings;
    const vector<unsigned char> pse = { '1', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1' };
    function<int(vector<string>& apps)>& appSelectionConfirmation;

    ExecutionResult pseSelect(vector<vector<unsigned char>>& aids, vector<TLV>& candidateList) {
        vector<unsigned char> resp;
        int sw1sw2 = command->select(pse, resp);

        if (sw1sw2 == 0x6A81) {
            return ExecutionResult::Terminate;  // card blocked || select not supported -> terminate
        }

        if (sw1sw2 != 0x9000) {  // PSE not found or other non-critical
            return ExecutionResult::Denied;
        }

        auto tags = TLV::parseTlv(resp);

        cout << tlvPrint(tags);

        auto sfi = tags.find(0x88)[0];

        int rec = 1;
        do {
            sw1sw2 = command->readRecord(sfi, rec++, resp);
            if (sw1sw2 == 0x9000) {
                auto recordTags = TLV::parseTlv(resp);
                cout << tlvPrint(recordTags);
                auto t4F = recordTags.find(0x4F);
                if (t4F.size() == 0) {
                    continue;
                }
                
                auto found = find_if(aids.begin(), aids.end(), [&t4F](const vector<unsigned char>& aid) {
                    return equal(t4F.begin(), t4F.end(), aid.begin());
                })!= aids.end();

                if (found) {
                    candidateList.emplace_back(recordTags);
                }else{
                    cout << "AID not in AIDs list" << endl;
                    vectorPrint(t4F);
                }
                
            }
        } while (sw1sw2 == 0x9000);

        return ExecutionResult::Success;
    }

    ExecutionResult directSelect(vector<vector<unsigned char>>& aids, vector<TLV>& candidateList, int partial) {
        vector<unsigned char> resp;
        bool selectNext = false;
        for (int i = 0; i < aids.size(); i++) {
            auto& aid = aids[i];

            int sw1sw2 = command->select(aid, resp, selectNext);
            selectNext = false;

            if (sw1sw2 == 0x6A81) {
                return ExecutionResult::Terminate;
            }

            if (sw1sw2 == 0x9000) {
                auto selectionTags = TLV::parseTlv(resp);
                vector<TLV> tlvs;

                auto t84 = selectionTags.find(0x84);
                if (!t84.size()) {
                    continue;
                }
                if (t84.size() != aid.size()) {
                    if (!partial) {
                        continue;
                    }
                    selectNext = true;
                    i--;
                }
                candidateList.push_back(selectionTags);
                cout << tlvPrint(selectionTags);
            }
        }
        return ExecutionResult::Success;
    }

    ExecutionResult buildCandidateList(vector<TLV>& candidateList, bool& confirmationNeeded) {
        vector<vector<unsigned char>> aids = settings.getAids();

        auto res = pseSelect(aids, candidateList);

        if (res == ExecutionResult::Terminate) {  // card blocked || select not supported -> terminate
            return ExecutionResult::Terminate;
        }

        if (res == ExecutionResult::Denied) {
            res = directSelect(aids, candidateList, 1);
        }

        for_each(candidateList.begin(), candidateList.end(), [&confirmationNeeded](TLV& t) {
            auto priorityIndicator = t.find(0x87);
            if (priorityIndicator.size()) {
                confirmationNeeded |= priorityIndicator[0] & 0x80;
            }
        });

        if (!candidateList.empty()) {
            sort(candidateList.begin(), candidateList.end(), [&](TLV& a, TLV& b) -> bool {
                auto priorityIndicatorA = a.find(0x87);
                auto priorityIndicatorB = b.find(0x87);

                if (priorityIndicatorA.size() && priorityIndicatorB.size())
                    return priorityIndicatorA[0] > priorityIndicatorB[0];
                else
                    return 0;
            });
        }

        return ExecutionResult::Success;
    }

    ExecutionResult appSelect() {
        vector<TLV> candidateList;
        bool confirmationNeeded;
        auto res = buildCandidateList(candidateList, confirmationNeeded);

        if (res == ExecutionResult::Terminate) {
            return ExecutionResult::Terminate;
        }

        if (candidateList.size() == 0) {
            return ExecutionResult::Terminate;
        }

        vector<string> appNames;
        for (auto& e : candidateList) {
            auto appName = e.find(0x50);
            if (appName.size()) {
                string s;
                for (auto& c : appName) {
                    s.push_back(c);
                }
                appNames.push_back(s);
            } else
                return ExecutionResult::Terminate;  // app with no label can't be processed
        }

        cout << "Apps found:" << endl;
        int no = 0;
        for_each(appNames.begin(), appNames.end(), [&no](string& s) { cout <<++no<<":"<< s << endl; });

        int appSelectedIndex = 0;
        if (candidateList.size() > 1 || confirmationNeeded) {
            appSelectedIndex = appSelectionConfirmation(appNames);
        }

        if (appSelectedIndex < 0 || appSelectedIndex >= candidateList.size()) {
            cout << "User cancelled" << endl;
            return ExecutionResult::Terminate;
        }

        auto& app2Select = candidateList[appSelectedIndex];

        cout <<endl<< "Selected app: " << appNames[appSelectedIndex] << endl;

        vector<vector<uint8_t>> app2SelectAidVector = { {} };

        auto aid = app2Select.find(0x4F);
        if (aid.size() == 0) {
            aid = app2Select.find(0x84);
        }

        for (auto& x : aid)
            app2SelectAidVector[0].push_back(x);

        vector<TLV> appList;

        res = directSelect(app2SelectAidVector, appList, 0);

        for (auto& setting : settings.getSettings()) {
            transactionObjects.put(setting.first, setting.second);
        }

        if (res == ExecutionResult::Success && appList.size() == 1) {
            cout << "App selected" << endl;
            transactionObjects.put(appList[0]);
        }
        return res;
    }

  public:
    Selection(TransactionObjects& _transactionObjects, Command* _command, Setttings& _settings,
              function<int(vector<string>& apps)>& _appSelectionConfirmation)
      : Operation(_transactionObjects, _command)
      , settings(_settings)
      , appSelectionConfirmation(_appSelectionConfirmation) {
    }

    ExecutionResult execute() override{
        cout << "***********************" << endl;
        cout << "[APPLICATION SELECTION]" << endl;
        cout << "***********************" << endl;
        try
        {
            return appSelect();
        }
        catch(const exception& e)
        {
            std::cerr << e.what() << '\n';
            return ExecutionResult::Terminate;
        }
    }

    ~Selection() override {
    }
};
#endif