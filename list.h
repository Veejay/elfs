#ifndef LIST_H
#define LIST_H

struct list;
typedef struct list tlist;

void list_free(struct list *q);
struct list *list_new(void);


typedef void (* tlist_free_func)(void *);
typedef int (* tlist_cmp_func)(void *, void *);

void list_set_free_func(struct list *list, tlist_free_func free_func);
void list_set_cmp_func(struct list *list, tlist_cmp_func cmp_func);

int list_get_size(struct list *q);
void list_add(struct list *q, void *elem);
void list_add_uniq(struct list *q, void *elem);
void list_extract(struct list *q, void *elem);
void *list_get(struct list *q, void *elem);
void *list_get_nth(tlist *q, int n);

#endif /* LIST_H */
