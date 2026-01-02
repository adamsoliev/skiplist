// Redis skiplist - extracted and simplified for benchmarking
// Original: Copyright (c) Redis Ltd. (BSD 3-Clause License)
// From: https://github.com/redis/redis/blob/unstable/src/t_zset.c

#include "zskiplist.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

// Element comparison - compare by bytes
int zslElementCompare(const zslElement* a, const char* b, size_t len) {
    size_t min_len = a->len < len ? a->len : len;
    int cmp = memcmp(a->data, b, min_len);
    if (cmp != 0) return cmp;
    if (a->len < len) return -1;
    if (a->len > len) return 1;
    return 0;
}

// Create a new element
static zslElement* zslElementCreate(const char* data, size_t len) {
    zslElement* ele = (zslElement*)malloc(sizeof(zslElement) + len);
    if (!ele) return NULL;
    ele->len = len;
    memcpy(ele->data, data, len);
    return ele;
}

// Free an element
static void zslElementFree(zslElement* ele) {
    free(ele);
}

// Random level using p=0.25
static int zslRandomLevel(void) {
    int level = 1;
    while ((rand() & 0xFFFF) < (ZSKIPLIST_P * 0xFFFF)) {
        level++;
    }
    return (level < ZSKIPLIST_MAXLEVEL) ? level : ZSKIPLIST_MAXLEVEL;
}

// Create a skiplist node
static zskiplistNode* zslCreateNode(int level, double score, zslElement* ele) {
    zskiplistNode* zn = (zskiplistNode*)malloc(
        sizeof(*zn) + level * sizeof(struct zskiplistLevel));
    if (!zn) return NULL;
    zn->score = score;
    zn->ele = ele;
    zn->backward = NULL;
    return zn;
}

// Free a skiplist node
static void zslFreeNode(zskiplistNode* node) {
    if (node->ele) {
        zslElementFree(node->ele);
    }
    free(node);
}

// Create a new skiplist
zskiplist* zslCreate(void) {
    int j;
    zskiplist* zsl;

    zsl = (zskiplist*)malloc(sizeof(*zsl));
    if (!zsl) return NULL;

    zsl->level = 1;
    zsl->length = 0;
    zsl->header = zslCreateNode(ZSKIPLIST_MAXLEVEL, 0, NULL);
    if (!zsl->header) {
        free(zsl);
        return NULL;
    }

    for (j = 0; j < ZSKIPLIST_MAXLEVEL; j++) {
        zsl->header->level[j].forward = NULL;
        zsl->header->level[j].span = 0;
    }
    zsl->header->backward = NULL;
    zsl->tail = NULL;
    return zsl;
}

// Free a skiplist
void zslFree(zskiplist* zsl) {
    zskiplistNode* node = zsl->header->level[0].forward;
    zskiplistNode* next;

    free(zsl->header);
    while (node) {
        next = node->level[0].forward;
        zslFreeNode(node);
        node = next;
    }
    free(zsl);
}

// Insert a new node
zskiplistNode* zslInsert(zskiplist* zsl, double score, const char* ele_data, size_t ele_len) {
    zskiplistNode* update[ZSKIPLIST_MAXLEVEL];
    zskiplistNode* x;
    unsigned long rank[ZSKIPLIST_MAXLEVEL];
    int i, level;

    assert(!isnan(score));

    x = zsl->header;
    for (i = zsl->level - 1; i >= 0; i--) {
        rank[i] = (i == (zsl->level - 1)) ? 0 : rank[i + 1];
        while (x->level[i].forward &&
               (x->level[i].forward->score < score ||
                (x->level[i].forward->score == score &&
                 zslElementCompare(x->level[i].forward->ele, ele_data, ele_len) < 0))) {
            rank[i] += x->level[i].span;
            x = x->level[i].forward;
        }
        update[i] = x;
    }

    level = zslRandomLevel();
    if (level > zsl->level) {
        for (i = zsl->level; i < level; i++) {
            rank[i] = 0;
            update[i] = zsl->header;
            update[i]->level[i].span = zsl->length;
        }
        zsl->level = level;
    }

    zslElement* ele = zslElementCreate(ele_data, ele_len);
    if (!ele) return NULL;

    x = zslCreateNode(level, score, ele);
    if (!x) {
        zslElementFree(ele);
        return NULL;
    }

    for (i = 0; i < level; i++) {
        x->level[i].forward = update[i]->level[i].forward;
        update[i]->level[i].forward = x;
        x->level[i].span = update[i]->level[i].span - (rank[0] - rank[i]);
        update[i]->level[i].span = (rank[0] - rank[i]) + 1;
    }

    for (i = level; i < zsl->level; i++) {
        update[i]->level[i].span++;
    }

    x->backward = (update[0] == zsl->header) ? NULL : update[0];
    if (x->level[0].forward) {
        x->level[0].forward->backward = x;
    } else {
        zsl->tail = x;
    }
    zsl->length++;
    return x;
}

// Internal delete helper
static void zslDeleteNode(zskiplist* zsl, zskiplistNode* x, zskiplistNode** update) {
    int i;
    for (i = 0; i < zsl->level; i++) {
        if (update[i]->level[i].forward == x) {
            update[i]->level[i].span += x->level[i].span - 1;
            update[i]->level[i].forward = x->level[i].forward;
        } else {
            update[i]->level[i].span -= 1;
        }
    }
    if (x->level[0].forward) {
        x->level[0].forward->backward = x->backward;
    } else {
        zsl->tail = x->backward;
    }
    while (zsl->level > 1 && zsl->header->level[zsl->level - 1].forward == NULL) {
        zsl->level--;
    }
    zsl->length--;
}

// Delete a node by score and element
int zslDelete(zskiplist* zsl, double score, const char* ele_data, size_t ele_len) {
    zskiplistNode* update[ZSKIPLIST_MAXLEVEL];
    zskiplistNode* x;
    int i;

    x = zsl->header;
    for (i = zsl->level - 1; i >= 0; i--) {
        while (x->level[i].forward &&
               (x->level[i].forward->score < score ||
                (x->level[i].forward->score == score &&
                 zslElementCompare(x->level[i].forward->ele, ele_data, ele_len) < 0))) {
            x = x->level[i].forward;
        }
        update[i] = x;
    }

    x = x->level[0].forward;
    if (x && score == x->score && zslElementCompare(x->ele, ele_data, ele_len) == 0) {
        zslDeleteNode(zsl, x, update);
        zslFreeNode(x);
        return 1;
    }
    return 0;
}

// Find a node by score and element
zskiplistNode* zslFind(zskiplist* zsl, double score, const char* ele_data, size_t ele_len) {
    zskiplistNode* x;
    int i;

    x = zsl->header;
    for (i = zsl->level - 1; i >= 0; i--) {
        while (x->level[i].forward &&
               (x->level[i].forward->score < score ||
                (x->level[i].forward->score == score &&
                 zslElementCompare(x->level[i].forward->ele, ele_data, ele_len) < 0))) {
            x = x->level[i].forward;
        }
    }

    x = x->level[0].forward;
    if (x && score == x->score && zslElementCompare(x->ele, ele_data, ele_len) == 0) {
        return x;
    }
    return NULL;
}

// Get rank of a node (1-based, 0 means not found)
unsigned long zslGetRank(zskiplist* zsl, double score, const char* ele_data, size_t ele_len) {
    zskiplistNode* x;
    unsigned long rank = 0;
    int i;

    x = zsl->header;
    for (i = zsl->level - 1; i >= 0; i--) {
        while (x->level[i].forward &&
               (x->level[i].forward->score < score ||
                (x->level[i].forward->score == score &&
                 zslElementCompare(x->level[i].forward->ele, ele_data, ele_len) <= 0))) {
            rank += x->level[i].span;
            x = x->level[i].forward;
        }
        if (x->ele && x->score == score &&
            zslElementCompare(x->ele, ele_data, ele_len) == 0) {
            return rank;
        }
    }
    return 0;
}

// Get first node
zskiplistNode* zslFirstNode(zskiplist* zsl) {
    return zsl->header->level[0].forward;
}
