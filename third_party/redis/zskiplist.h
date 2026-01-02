// Redis skiplist - extracted and simplified for benchmarking
// Original: Copyright (c) Redis Ltd. (BSD 3-Clause License)
// From: https://github.com/redis/redis/blob/unstable/src/t_zset.c

#ifndef ZSKIPLIST_H
#define ZSKIPLIST_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZSKIPLIST_MAXLEVEL 32
#define ZSKIPLIST_P 0.25

// Simplified element type - just a length-prefixed string
typedef struct zslElement {
    size_t len;
    char data[];
} zslElement;

typedef struct zskiplistNode {
    zslElement* ele;
    double score;
    struct zskiplistNode* backward;
    struct zskiplistLevel {
        struct zskiplistNode* forward;
        unsigned long span;
    } level[];
} zskiplistNode;

typedef struct zskiplist {
    struct zskiplistNode* header;
    struct zskiplistNode* tail;
    unsigned long length;
    int level;
} zskiplist;

// Public API
zskiplist* zslCreate(void);
void zslFree(zskiplist* zsl);
zskiplistNode* zslInsert(zskiplist* zsl, double score, const char* ele, size_t len);
int zslDelete(zskiplist* zsl, double score, const char* ele, size_t len);
zskiplistNode* zslFind(zskiplist* zsl, double score, const char* ele, size_t len);
unsigned long zslGetRank(zskiplist* zsl, double score, const char* ele, size_t len);
zskiplistNode* zslFirstNode(zskiplist* zsl);

// Element comparison
int zslElementCompare(const zslElement* a, const char* b, size_t len);

#ifdef __cplusplus
}
#endif

#endif // ZSKIPLIST_H
