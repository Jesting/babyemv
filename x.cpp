#include "babyemv/kernel.hpp"
#include "babyemv/reader.hpp"

using namespace std;

int select(vector<string>& apps) {
    for_each(apps.begin(), apps.end(), [](const string& x) { cout << x << endl; });
    cout << "Select app:" << endl;
    int no = 0;
    cin >> no;
    if (no < 0 || no >= apps.size()) {
        cout << "Invalid selection" << endl;
        return -1;
    }
    return no;
}

vector<uint8_t> pin() {
    vector<uint8_t> pin;
    cout << "ENTER PIN: " << endl;
    char ch;    
    string input;
    cin >> input;
    for (char ch : input) {
        if (isdigit(ch)) {
            pin.push_back(ch - '0');
        }else{
            cout << "Invalid character, only digits are allowed" << endl;
            return {};
        }   
    }
    cout << "PIN:" << endl;
    vectorPrint(pin);
    return pin;
}



void online(const unordered_map<uint32_t, vector<uint8_t>>& t, vector<pair<uint8_t, vector<uint8_t>>>& response) {
    // response.push_back({0x91, { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }});
    //^don't have original data, so just omitting it cause later it would be automatically calculated by DOL builder

    response.push_back({ 0x8A, { 0x30, 0x30 } });
}

int main() {
    auto c = ScardApiReader();
    c.listReaders();
    c.connectByName("HID Global OMNIKEY 5422 Smartcard Reader 01");  // CL
    //c.connectByName("HID Global OMNIKEY 5422 Smartcard Reader");  // CT

    SampleSettings s;
    SelectionCallback selectionCallback = select;
    PinEntryCallback pinEntryCallback = pin;
    OnlineRequestCallback onlineRequestCallback = online;

    Kernel k(s, c, selectionCallback, pinEntryCallback, onlineRequestCallback);

    if (k.peformOperation(1500, 0, 0x00, 250309, 981)) {
        cout << "Transaction approved" << endl;
    } else {
        cout << "Transaction denied" << endl;
    }

    return 0;
};
