#ifndef __COMMAND__
#define __COMMAND__

#include <iostream>
#include <vector>
#include <array>
#include <span>
#include "reader.hpp"

using namespace std;

class Command {
    Reader& reader;

  public:
    Command(Reader& _reader):reader(_reader) {}
    int reset() {
        return 0;
    }

    int getResponse(vector<unsigned char>& response, unsigned char le) {
        array<unsigned char, 5> apdu = { 0x00, 0xC0, 0x00, 0x00, le };

        array<unsigned char, 255> buf;
        unsigned int len = 255;
        int res = reader.command(apdu.data(), apdu.size(), buf.data(), len);

        int sw1sw2 = -1;

        if (res == 0) {
            sw1sw2 = buf[len - 2] << 8 | buf[len - 1];
            for (int i = 0; i < len - 2; i++)
                response.push_back(buf[i]);
        }

        return sw1sw2;
    }

    inline int command_(vector<unsigned char>& apdu, vector<unsigned char>& response) {
        response.clear();

        unsigned int len = 1024;
        array<unsigned char, 1024> buf;
        int res = reader.command(apdu.data(), apdu.size(), buf.data(), len);

        if (res != 0)
            return -1;
        if (len < 2)
            return -1;

        int sw1sw2 = buf[len - 2] << 8 | buf[len - 1];

        for (int i = 0; i < len - 2; i++)
            response.push_back(buf[i]);

        while ((sw1sw2 & 0xFF00) == 0x6100) {
            sw1sw2 = getResponse(response, sw1sw2);
        }

        return sw1sw2;
    }

    int commandWrapper(vector<unsigned char>& apdu, vector<unsigned char>& response) {
        auto sw1sw2 = command_(apdu, response);

        if ((sw1sw2 & 0x6C00) == 0x6C00) {
            apdu[apdu.size() - 1] = sw1sw2;
            sw1sw2 = command_(apdu, response);
        }

        return sw1sw2;
    }

    int select(const vector<unsigned char>& aid, vector<unsigned char>& response, bool selectNext = false) {
        vector<unsigned char> apdu = { 0x00, 0xA4, 0x04 };
        if (selectNext)
            apdu.push_back(0x02);
        else
            apdu.push_back(0x00);
        apdu.push_back(aid.size());
        apdu.insert(apdu.end(), aid.begin(), aid.end());
        apdu.push_back(0x00);

        auto resp = commandWrapper(apdu, response);
        return resp;
    }

    int readRecord(unsigned char sfi, unsigned char recordNo, vector<unsigned char>& response) {
        vector<unsigned char> apdu = { 0x00, 0xB2, recordNo, static_cast<unsigned char>(sfi << 3 | 4), 0x00 };

        return commandWrapper(apdu, response);
    }

    int getData(int tag, vector<unsigned char>& response) {
        vector<unsigned char> apdu = { 0x80, 0xCA, static_cast<unsigned char>(tag >> 8),
                                       static_cast<unsigned char>(tag), 0x00 };

        return commandWrapper(apdu, response);
    }

    int gpo(const vector<unsigned char>& data, vector<unsigned char>& response) {
        vector<unsigned char> apdu = { 0x80, 0xA8, 0, 0, static_cast<unsigned char>(data.size()) };

        apdu.insert(apdu.end(), data.begin(), data.end());
        apdu.push_back(0x00);

        return commandWrapper(apdu, response);
    }

    int getChallenge(vector<unsigned char>& response) {
        vector<unsigned char> apdu = { 0x00, 0x84, 0x00, 0x00, 0x08 };

        return commandWrapper(apdu, response);
    }

    int verify(bool plain, const vector<unsigned char>& data) {
        vector<unsigned char> apdu = { 0x00, 0x20, 0x00 };

        if (plain)
            apdu.push_back(0x80);
        else
            apdu.push_back(0x88);
        apdu.push_back(data.size());

        apdu.insert(apdu.end(), data.begin(), data.end());

        vector<unsigned char> response;
        return commandWrapper(apdu, response);
    }

    int internalAuthenticate(const vector<unsigned char> data, vector<unsigned char>& response) {
        vector<unsigned char> apdu = { 0x00, 0x88, 0x00, 0x00, static_cast<unsigned char>(data.size()) };

        apdu.insert(apdu.end(), data.begin(), data.end());

        apdu.push_back(0x00);

        return commandWrapper(apdu, response);
    }

    int genAc(uint8_t ac, bool signature, const vector<unsigned char> data, vector<unsigned char>& response) {
        unsigned char p1 = ac;
        if (signature)
            p1 |= 0x10;

        vector<unsigned char> apdu = { 0x80, 0xAE, p1, 0x00, static_cast<unsigned char>(data.size()) };

        apdu.insert(apdu.end(), data.begin(), data.end());

        apdu.push_back(0x00);

        return commandWrapper(apdu, response);
    }
};

#endif