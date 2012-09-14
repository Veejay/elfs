#ifndef LIST_H
#define LIST_H

struct list;
typedef struct list tlist;

void list_free(struct list *q);
struct list *list_new(void);


typedef void (* tlist_free_func)(void *);
typedef int (* tlist_cmp_func)(void *, void *);
typedef void (* tlist_map_func)(void *, void *);

void list_set_free_func(tlist *list, tlist_free_func free_func);
void list_set_cmp_func(tlist *list, tlist_cmp_func cmp_func);

int list_get_size(tlist *q);
void list_add(tlist *q, void *elem);
int list_add_uniq(tlist *q, void *elem);
void list_extract(tlist *q, void *elem);
void *list_get(tlist *q, void *elem);
void *list_get_nth(tlist *q, int n);
void list_map(tlist *q, tlist_map_func map, void *ctx);

#endif /* LIST_H */
