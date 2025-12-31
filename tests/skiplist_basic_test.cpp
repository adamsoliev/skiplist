#include <gtest/gtest.h>

#include "../src/skiplist.hpp"

using namespace minilsm;

class SkipListBasicTest : public ::testing::Test
{
      protected:
        void SetUp() override
        {
                arena_ = std::make_unique<Arena>();
                list_ = std::make_unique<SkipList>(arena_.get());
        }

        void insert(const std::string &key, uint64_t seq, const std::string &value, KeyType type = KeyType::Put)
        {
                list_->insert(InternalKey(key, seq, type), value);
        }

        std::unique_ptr<Arena> arena_;
        std::unique_ptr<SkipList> list_;
};

// Empty List Behavior

TEST_F(SkipListBasicTest, EmptyListGetReturnsNotFound)
{
        std::string value;
        EXPECT_FALSE(list_->get("any_key", &value));
}

TEST_F(SkipListBasicTest, EmptyListGetWithNullValue) { EXPECT_FALSE(list_->get("any_key", nullptr)); }

TEST_F(SkipListBasicTest, EmptyListIteratorNotValid)
{
        SkipList::Iterator iter(list_.get());
        iter.seek_to_first();
        EXPECT_FALSE(iter.valid());
}

TEST_F(SkipListBasicTest, EmptyListSeekToLastNotValid)
{
        SkipList::Iterator iter(list_.get());
        iter.seek_to_last();
        EXPECT_FALSE(iter.valid());
}

TEST_F(SkipListBasicTest, EmptyListSeekNotValid)
{
        SkipList::Iterator iter(list_.get());
        iter.seek("any_key");
        EXPECT_FALSE(iter.valid());
}

// Single Element Operations

TEST_F(SkipListBasicTest, InsertAndGetSingleElement)
{
        insert("key1", 1, "value1");

        std::string value;
        EXPECT_TRUE(list_->get("key1", &value));
        EXPECT_EQ(value, "value1");
}

TEST_F(SkipListBasicTest, GetNonExistentKeyAfterInsert)
{
        insert("key1", 1, "value1");

        std::string value;
        EXPECT_FALSE(list_->get("key2", &value));
}

TEST_F(SkipListBasicTest, GetWithNullValuePointer)
{
        insert("key1", 1, "value1");
        EXPECT_TRUE(list_->get("key1", nullptr));
}

// Multiple Elements - Ordering

TEST_F(SkipListBasicTest, InsertMultipleKeysInOrder)
{
        insert("aaa", 1, "val_a");
        insert("bbb", 2, "val_b");
        insert("ccc", 3, "val_c");

        std::string value;
        EXPECT_TRUE(list_->get("aaa", &value));
        EXPECT_EQ(value, "val_a");
        EXPECT_TRUE(list_->get("bbb", &value));
        EXPECT_EQ(value, "val_b");
        EXPECT_TRUE(list_->get("ccc", &value));
        EXPECT_EQ(value, "val_c");
}

TEST_F(SkipListBasicTest, InsertMultipleKeysReverseOrder)
{
        insert("ccc", 1, "val_c");
        insert("bbb", 2, "val_b");
        insert("aaa", 3, "val_a");

        std::string value;
        EXPECT_TRUE(list_->get("aaa", &value));
        EXPECT_EQ(value, "val_a");
        EXPECT_TRUE(list_->get("bbb", &value));
        EXPECT_EQ(value, "val_b");
        EXPECT_TRUE(list_->get("ccc", &value));
        EXPECT_EQ(value, "val_c");
}

TEST_F(SkipListBasicTest, InsertMultipleKeysRandomOrder)
{
        insert("dog", 1, "woof");
        insert("cat", 2, "meow");
        insert("bird", 3, "chirp");
        insert("fish", 4, "blub");

        std::string value;
        EXPECT_TRUE(list_->get("bird", &value));
        EXPECT_EQ(value, "chirp");
        EXPECT_TRUE(list_->get("cat", &value));
        EXPECT_EQ(value, "meow");
        EXPECT_TRUE(list_->get("dog", &value));
        EXPECT_EQ(value, "woof");
        EXPECT_TRUE(list_->get("fish", &value));
        EXPECT_EQ(value, "blub");
}

// Version Handling (Same user_key, different sequences)

TEST_F(SkipListBasicTest, NewerVersionOverridesOlder)
{
        insert("key", 1, "old_value");
        insert("key", 2, "new_value");

        std::string value;
        EXPECT_TRUE(list_->get("key", &value));
        EXPECT_EQ(value, "new_value");
}

TEST_F(SkipListBasicTest, InsertNewerThenOlderStillReturnsNewer)
{
        insert("key", 10, "newer_value");
        insert("key", 5, "older_value");

        std::string value;
        EXPECT_TRUE(list_->get("key", &value));
        EXPECT_EQ(value, "newer_value");
}

TEST_F(SkipListBasicTest, MultipleVersionsAllStored)
{
        insert("key", 1, "v1");
        insert("key", 2, "v2");
        insert("key", 3, "v3");

        // Get returns newest
        std::string value;
        EXPECT_TRUE(list_->get("key", &value));
        EXPECT_EQ(value, "v3");

        // Iterator should see all versions (newest first due to seq DESC)
        SkipList::Iterator iter(list_.get());
        iter.seek_to_first();

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "key");
        EXPECT_EQ(iter.key().sequence, 3u);
        EXPECT_EQ(iter.value().to_string(), "v3");

        iter.next();
        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().sequence, 2u);
        EXPECT_EQ(iter.value().to_string(), "v2");

        iter.next();
        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().sequence, 1u);
        EXPECT_EQ(iter.value().to_string(), "v1");

        iter.next();
        EXPECT_FALSE(iter.valid());
}

// Delete (Tombstone) Handling

TEST_F(SkipListBasicTest, DeleteMakesKeyNotFound)
{
        insert("key", 1, "value");
        insert("key", 2, "", KeyType::Delete);

        std::string value;
        EXPECT_FALSE(list_->get("key", &value));
}

TEST_F(SkipListBasicTest, InsertAfterDeleteRestoresKey)
{
        insert("key", 1, "v1");
        insert("key", 2, "", KeyType::Delete);
        insert("key", 3, "v3");

        std::string value;
        EXPECT_TRUE(list_->get("key", &value));
        EXPECT_EQ(value, "v3");
}

TEST_F(SkipListBasicTest, OlderDeleteDoesNotAffectNewerPut)
{
        insert("key", 2, "value");
        insert("key", 1, "", KeyType::Delete);

        std::string value;
        EXPECT_TRUE(list_->get("key", &value));
        EXPECT_EQ(value, "value");
}

// Edge Cases

TEST_F(SkipListBasicTest, EmptyKeyAndValue)
{
        insert("", 1, "");

        std::string value;
        EXPECT_TRUE(list_->get("", &value));
        EXPECT_EQ(value, "");
}

TEST_F(SkipListBasicTest, LongKeyAndValue)
{
        std::string long_key(1000, 'k');
        std::string long_value(10000, 'v');

        insert(long_key, 1, long_value);

        std::string value;
        EXPECT_TRUE(list_->get(long_key, &value));
        EXPECT_EQ(value, long_value);
}

TEST_F(SkipListBasicTest, BinaryDataInKeyAndValue)
{
        std::string binary_key = "key\x00with\x00nulls";
        binary_key.resize(15); // ensure nulls are included
        std::string binary_value = "val\x00ue";
        binary_value.resize(6);

        list_->insert(
            InternalKey(Slice(binary_key.data(), binary_key.size()), 1, KeyType::Put),
            Slice(binary_value.data(), binary_value.size()));

        std::string value;
        EXPECT_TRUE(list_->get(Slice(binary_key.data(), binary_key.size()), &value));
        EXPECT_EQ(value, binary_value);
}

TEST_F(SkipListBasicTest, ManyInserts)
{
        const int N = 1000;
        for (int i = 0; i < N; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string value = "value" + std::to_string(i);
                insert(key, i + 1, value);
        }

        // Verify all keys
        for (int i = 0; i < N; i++)
        {
                std::string key = "key" + std::to_string(i);
                std::string expected_value = "value" + std::to_string(i);
                std::string value;
                EXPECT_TRUE(list_->get(key, &value)) << "Failed for key: " << key;
                EXPECT_EQ(value, expected_value);
        }
}

// Arena Memory Usage

TEST_F(SkipListBasicTest, ArenaMemoryGrowsWithInserts)
{
        size_t initial_usage = arena_->memory_usage();

        insert("key1", 1, "value1");
        size_t after_one = arena_->memory_usage();
        EXPECT_GE(after_one, initial_usage);

        for (int i = 0; i < 100; i++)
        {
                insert("key" + std::to_string(i), i + 2, "value" + std::to_string(i));
        }
        size_t after_many = arena_->memory_usage();
        EXPECT_GT(after_many, after_one);
}
