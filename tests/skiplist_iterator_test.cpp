#include <gtest/gtest.h>

#include "../src/skiplist.hpp"
#include <vector>

using namespace minilsm;

class SkipListIteratorTest : public ::testing::Test
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

        void populate_list()
        {
                // Insert in random order; skiplist will maintain sorted order
                insert("charlie", 3, "c_val");
                insert("alice", 1, "a_val");
                insert("eve", 5, "e_val");
                insert("bob", 2, "b_val");
                insert("david", 4, "d_val");
        }

        std::unique_ptr<Arena> arena_;
        std::unique_ptr<SkipList> list_;
};

// ============================================================================
// Forward Iteration
// ============================================================================

TEST_F(SkipListIteratorTest, SeekToFirstForwardIteration)
{
        populate_list();

        std::vector<std::string> expected = {"alice", "bob", "charlie", "david", "eve"};
        std::vector<std::string> actual;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_first(); iter.valid(); iter.next()) {
                actual.push_back(iter.key().user_key.to_string());
        }

        EXPECT_EQ(actual, expected);
}

TEST_F(SkipListIteratorTest, ForwardIterationValues)
{
        populate_list();

        std::vector<std::string> expected_values = {"a_val", "b_val", "c_val", "d_val", "e_val"};
        std::vector<std::string> actual_values;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_first(); iter.valid(); iter.next()) {
                actual_values.push_back(iter.value().to_string());
        }

        EXPECT_EQ(actual_values, expected_values);
}

TEST_F(SkipListIteratorTest, ForwardIterationWithVersions)
{
        insert("key", 1, "v1");
        insert("key", 3, "v3");
        insert("key", 2, "v2");

        std::vector<std::pair<uint64_t, std::string>> expected = {{3, "v3"}, {2, "v2"}, {1, "v1"}};
        std::vector<std::pair<uint64_t, std::string>> actual;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_first(); iter.valid(); iter.next()) {
                actual.emplace_back(iter.key().sequence, iter.value().to_string());
        }

        EXPECT_EQ(actual, expected);
}

// ============================================================================
// Backward Iteration
// ============================================================================

TEST_F(SkipListIteratorTest, SeekToLastBackwardIteration)
{
        populate_list();

        std::vector<std::string> expected = {"eve", "david", "charlie", "bob", "alice"};
        std::vector<std::string> actual;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_last(); iter.valid(); iter.prev()) {
                actual.push_back(iter.key().user_key.to_string());
        }

        EXPECT_EQ(actual, expected);
}

TEST_F(SkipListIteratorTest, BackwardIterationValues)
{
        populate_list();

        std::vector<std::string> expected_values = {"e_val", "d_val", "c_val", "b_val", "a_val"};
        std::vector<std::string> actual_values;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_last(); iter.valid(); iter.prev()) {
                actual_values.push_back(iter.value().to_string());
        }

        EXPECT_EQ(actual_values, expected_values);
}

TEST_F(SkipListIteratorTest, BackwardIterationWithVersions)
{
        insert("key", 1, "v1");
        insert("key", 3, "v3");
        insert("key", 2, "v2");

        std::vector<std::pair<uint64_t, std::string>> expected = {{1, "v1"}, {2, "v2"}, {3, "v3"}};
        std::vector<std::pair<uint64_t, std::string>> actual;

        SkipList::Iterator iter(list_.get());
        for (iter.seek_to_last(); iter.valid(); iter.prev()) {
                actual.emplace_back(iter.key().sequence, iter.value().to_string());
        }

        EXPECT_EQ(actual, expected);
}

// ============================================================================
// Seek Operations
// ============================================================================

TEST_F(SkipListIteratorTest, SeekToExistingKey)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek("charlie");

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "charlie");
        EXPECT_EQ(iter.value().to_string(), "c_val");
}

TEST_F(SkipListIteratorTest, SeekToNonExistingKeyLandsOnNext)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek("bobby"); // between bob and charlie

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "charlie");
}

TEST_F(SkipListIteratorTest, SeekPastLastKeyInvalidates)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek("zzz"); // after eve

        EXPECT_FALSE(iter.valid());
}

TEST_F(SkipListIteratorTest, SeekBeforeFirstKeyLandsOnFirst)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek("aaa"); // before alice

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "alice");
}

TEST_F(SkipListIteratorTest, SeekToKeyWithMultipleVersions)
{
        insert("key", 1, "v1");
        insert("key", 5, "v5");
        insert("key", 3, "v3");

        SkipList::Iterator iter(list_.get());
        iter.seek("key");

        // Should land on newest version (highest sequence)
        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "key");
        EXPECT_EQ(iter.key().sequence, 5u);
        EXPECT_EQ(iter.value().to_string(), "v5");
}

// ============================================================================
// Mixed Forward/Backward Navigation
// ============================================================================

TEST_F(SkipListIteratorTest, ForwardThenBackward)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek_to_first();

        // Move forward: alice -> bob -> charlie
        EXPECT_EQ(iter.key().user_key.to_string(), "alice");
        iter.next();
        EXPECT_EQ(iter.key().user_key.to_string(), "bob");
        iter.next();
        EXPECT_EQ(iter.key().user_key.to_string(), "charlie");

        // Move backward: charlie -> bob -> alice
        iter.prev();
        EXPECT_EQ(iter.key().user_key.to_string(), "bob");
        iter.prev();
        EXPECT_EQ(iter.key().user_key.to_string(), "alice");
}

TEST_F(SkipListIteratorTest, BackwardThenForward)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek_to_last();

        // Move backward: eve -> david -> charlie
        EXPECT_EQ(iter.key().user_key.to_string(), "eve");
        iter.prev();
        EXPECT_EQ(iter.key().user_key.to_string(), "david");
        iter.prev();
        EXPECT_EQ(iter.key().user_key.to_string(), "charlie");

        // Move forward: charlie -> david -> eve
        iter.next();
        EXPECT_EQ(iter.key().user_key.to_string(), "david");
        iter.next();
        EXPECT_EQ(iter.key().user_key.to_string(), "eve");
}

TEST_F(SkipListIteratorTest, PrevAtFirstInvalidates)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek_to_first();
        EXPECT_EQ(iter.key().user_key.to_string(), "alice");

        iter.prev();
        EXPECT_FALSE(iter.valid());
}

TEST_F(SkipListIteratorTest, NextAtLastInvalidates)
{
        populate_list();

        SkipList::Iterator iter(list_.get());
        iter.seek_to_last();
        EXPECT_EQ(iter.key().user_key.to_string(), "eve");

        iter.next();
        EXPECT_FALSE(iter.valid());
}

// ============================================================================
// Single Element List
// ============================================================================

TEST_F(SkipListIteratorTest, SingleElementForward)
{
        insert("only", 1, "one");

        SkipList::Iterator iter(list_.get());
        iter.seek_to_first();

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "only");

        iter.next();
        EXPECT_FALSE(iter.valid());
}

TEST_F(SkipListIteratorTest, SingleElementBackward)
{
        insert("only", 1, "one");

        SkipList::Iterator iter(list_.get());
        iter.seek_to_last();

        ASSERT_TRUE(iter.valid());
        EXPECT_EQ(iter.key().user_key.to_string(), "only");

        iter.prev();
        EXPECT_FALSE(iter.valid());
}

// ============================================================================
// Large List Iteration
// ============================================================================

TEST_F(SkipListIteratorTest, LargeListForwardIteration)
{
        const int N = 1000;
        for (int i = 0; i < N; i++) {
                // Insert keys that sort numerically correctly
                char key[16];
                snprintf(key, sizeof(key), "key%06d", i);
                insert(key, i + 1, std::to_string(i));
        }

        SkipList::Iterator iter(list_.get());
        int count = 0;
        int prev_num = -1;

        for (iter.seek_to_first(); iter.valid(); iter.next()) {
                std::string key = iter.key().user_key.to_string();
                int num = std::stoi(key.substr(3));
                EXPECT_GT(num, prev_num) << "Keys should be in ascending order";
                prev_num = num;
                count++;
        }

        EXPECT_EQ(count, N);
}

TEST_F(SkipListIteratorTest, LargeListBackwardIteration)
{
        const int N = 1000;
        for (int i = 0; i < N; i++) {
                char key[16];
                snprintf(key, sizeof(key), "key%06d", i);
                insert(key, i + 1, std::to_string(i));
        }

        SkipList::Iterator iter(list_.get());
        int count = 0;
        int prev_num = N;

        for (iter.seek_to_last(); iter.valid(); iter.prev()) {
                std::string key = iter.key().user_key.to_string();
                int num = std::stoi(key.substr(3));
                EXPECT_LT(num, prev_num) << "Keys should be in descending order during backward iteration";
                prev_num = num;
                count++;
        }

        EXPECT_EQ(count, N);
}

// ============================================================================
// Iterator Independence
// ============================================================================

TEST_F(SkipListIteratorTest, MultipleIteratorsIndependent)
{
        populate_list();

        SkipList::Iterator iter1(list_.get());
        SkipList::Iterator iter2(list_.get());

        iter1.seek_to_first();
        iter2.seek_to_last();

        EXPECT_EQ(iter1.key().user_key.to_string(), "alice");
        EXPECT_EQ(iter2.key().user_key.to_string(), "eve");

        iter1.next();
        EXPECT_EQ(iter1.key().user_key.to_string(), "bob");
        EXPECT_EQ(iter2.key().user_key.to_string(), "eve"); // unchanged

        iter2.prev();
        EXPECT_EQ(iter1.key().user_key.to_string(), "bob"); // unchanged
        EXPECT_EQ(iter2.key().user_key.to_string(), "david");
}
