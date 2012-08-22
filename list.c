#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "list.h"


typedef struct node {
        void *elem;
        struct node *next;
} tnode;

struct list {
        tnode *head;

        int size;

        tlist_free_func free_func;
        tlist_cmp_func cmp_func;
};

void
list_free(tlist *q)
{
        if (! q)
                return;

        tnode *node = q->head;

        while (node) {
                tnode *dummy = node;
                node = node->next;
                q->free_func(dummy->elem);
                free(dummy);
        }

        free(q);
}

static int
list_default_cmp(void *a,
                 void *b)
{
        if ((uintptr_t) a < (uintptr_t) b)
                return -1;

        if ((uintptr_t) a > (uintptr_t) b)
                return 1;

        return 0;
}

tlist *
list_new(void)
{
        tlist *q = malloc(sizeof *q);
        if (! q)
                return NULL;

        q->head = NULL;
        q->size = 0;

        /* default: the stdlib free() function */
        q->free_func = free;
        q->cmp_func = list_default_cmp;

        return q;
}

void
list_set_free_func(tlist *list,
                   tlist_free_func free_func)
{
        list->free_func = free_func;
}

void
list_set_cmp_func(tlist *list,
                  tlist_cmp_func cmp_func)
{
        list->cmp_func = cmp_func;
}

int
list_get_size(tlist *q)
{
        if (! q)
                return -1;

        return q->size;
}

void
list_add(tlist *q,
         void *elem)
{
        if (! elem)
                return;

        tnode *node = malloc(sizeof *node);
        if (! node) {
                perror("malloc");
                return;
        }

        node->elem = elem;
        node->next = q->head;
        q->head = node;

        q->size++;
}

void *
list_get(tlist *q,
         void *key)
{
        if (! q || 0 == q->size)
                return NULL;

        tnode *node = q->head;

        while (node) {
                if (0 == q->cmp_func(key, node->elem))
                        return node->elem;

                node = node->next;
        }

        return NULL;
}

void *
list_get_nth(tlist *q,
             int n)
{
        if (! q || n >= q->size)
                return NULL;

        tnode *node = q->head;

        while (n > 0) {
                node = node->next;
                n--;
        }

        return node->elem;
}

/* if we don't want any duplicate, use this function (slow) */
void
list_add_uniq(tlist *q,
              void *elem)
{
        if (! elem)
                return;

        if (list_get(q, elem))
                return;

        tnode *node = malloc(sizeof *node);
        if (! node) {
                perror("malloc");
                return;
        }

        node->elem = elem;
        node->next = NULL;

        q->size++;
}

void
list_extract(tlist *q,
             void *elem)
{
        if (! q || 0 == q->size)
                return;

        tnode *node = q->head;
        tnode *backup = node;

        while (node) {
                if (0 == q->cmp_func(elem, node->elem)) {
                        backup->next = node->next;
                        q->size--;

                        return;
                }

                backup = node;
                node = node->next;
        }
}
