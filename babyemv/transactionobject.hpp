#ifndef __TRANACTIONOBJECTS__
#define __TRANACTIONOBJECTS__
#include <unordered_map>
#include <vector>
#include <format>
#include "tlv.hpp"
#include "utils.hpp"

using namespace std;
class TransactionObjects;
class TransactionObject {
  protected:
    vector<uint8_t>& value;

  public:
    explicit TransactionObject(vector<uint8_t>& _value) : value(_value) {
    }
    virtual ~TransactionObject() {
    }
};

class TransactionObjectEx : TransactionObject {
  protected:
    TransactionObjects& transactionObjects;

  public:
    TransactionObjectEx(vector<unsigned char>& _value, TransactionObjects& _transactionObjects)
      : TransactionObject(_value), transactionObjects(_transactionObjects) {
    }
    virtual ~TransactionObjectEx() {
    }
};

class TransactionObjects {
    unordered_map<uint32_t, vector<uint8_t>> tags;

  public:
    const unordered_map<uint32_t, vector<uint8_t>> getMap() {
        return tags;
    }
    
    void put(TLV& tag) {
        if (tag.tags.size()) {
            for (auto& t : tag.tags)
                put(t);
        } else {
            auto v = vector<unsigned char>();
            v.assign(tag.V().begin(), tag.V().end());
            tags[tag.T] = v;

            //cout << format("Added tag:{:04X}\n", tag.T);
        }
    }

    void put(uint32_t tag, const vector<uint8_t>& value) {
        tags[tag] = value;
        //cout << format("Added tag:{:04X}\n", tag);
    }

    vector<uint8_t>* get(uint32_t tag) {
        if (tags.contains(tag)) {
            return &tags[tag];
        } else
            return nullptr;
    }

    vector<uint8_t>* getOrDefault(uint32_t tag, const vector<uint8_t>& deflt) {
        if (tags.contains(tag)) {
            return &tags[tag];
        } else {
            put(tag, deflt);
            return &tags[tag];
        }
    }

    template <class T>
    shared_ptr<T> get(uint32_t tag) {
        static_assert(is_base_of<TransactionObject, T>::value, "T must be derived from TransactionObject");
        auto value = get(tag);
        if (value != nullptr) {
            if constexpr (is_base_of<TransactionObjectEx, T>::value) {
                return make_shared<T>(*value, *this);
            } else
                return make_shared<T>(T(*value));
        } else
            return nullptr;
    }

    template <class T>
    shared_ptr<T> put(uint32_t tag, const vector<uint8_t>& _value) {
        static_assert(is_base_of<TransactionObject, T>::value, "T must be derived from TransactionObject");
        put(tag, _value);
        auto value = get(tag);
        if (value != nullptr) {
            if constexpr (is_base_of<TransactionObjectEx, T>::value) {
                return make_shared<T>(*value, *this);
            } else
                return make_shared<T>(T(*value));
        } else
            return nullptr;
    }
};
#endif