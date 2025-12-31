#include "skiplist.hpp"
#include <iostream>

int main()
{
        minilsm::Arena arena;
        minilsm::SkipList skiplist(&arena);

        // Insert some key-value pairs
        uint64_t seq = 1;
        skiplist.insert(minilsm::InternalKey("apple", seq++, minilsm::KeyType::Put), "red");
        skiplist.insert(minilsm::InternalKey("fig", seq++, minilsm::KeyType::Put), "purple");
        skiplist.insert(minilsm::InternalKey("banana", seq++, minilsm::KeyType::Put), "yellow");
        skiplist.insert(minilsm::InternalKey("kiwi", seq++, minilsm::KeyType::Put), "brown");
        skiplist.insert(minilsm::InternalKey("cherry", seq++, minilsm::KeyType::Put), "red");
        skiplist.insert(minilsm::InternalKey("orange", seq++, minilsm::KeyType::Put), "orange");

        // Update apple with newer version
        skiplist.insert(minilsm::InternalKey("apple", seq++, minilsm::KeyType::Put), "green");

        // Point lookups
        std::string value;
        if (skiplist.get("apple", &value))
        {
                std::cout << "apple = " << value << std::endl; // should be "green"
        }
        if (skiplist.get("banana", &value))
        {
                std::cout << "banana = " << value << std::endl;
        }
        if (!skiplist.get("grape", &value))
        {
                std::cout << "grape not found" << std::endl;
        }

        // Iterator scan
        std::cout << "\nAll entries (sorted):" << std::endl;
        minilsm::SkipList::Iterator iter(&skiplist);
        for (iter.seek_to_first(); iter.valid(); iter.next())
        {
                std::cout << "  " << iter.key().user_key.to_string() << " (seq=" << iter.key().sequence
                          << ") = " << iter.value().to_string() << std::endl;
        }

        // Seek to specific key
        std::cout << "\nSeek to 'banana':" << std::endl;
        iter.seek("banana");
        while (iter.valid())
        {
                std::cout << "  " << iter.key().user_key.to_string() << " = " << iter.value().to_string() << std::endl;
                iter.next();
        }

        std::cout << "\nArena memory usage: " << arena.memory_usage() << " bytes" << std::endl;

        return 0;
}
