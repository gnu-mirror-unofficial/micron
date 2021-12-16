/* GNU micron - a minimal cron implementation
   Copyright (C) 2020-2021 Sergey Poznyakoff

   GNU micron is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3 of the License, or (at your
   option) any later version.

   GNU micron is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with GNU micron. If not, see <http://www.gnu.org/licenses/>. */

struct list_head {
    struct list_head *prev, *next;
};

#define LIST_HEAD_INITIALIZER(h) { &(h), &(h) }

static inline void
list_head_init(struct list_head *head)
{
    head->next = head->prev = head;
}

static inline int
list_head_is_empty(struct list_head *head)
{
    return head->next == head && head->prev == head;
}

static inline void
list_head_remove(struct list_head *head)
{
    head->prev->next = head->next;
    head->next->prev = head->prev;
    list_head_init(head);
}

static inline void
list_head_insert_after(struct list_head *a, struct list_head *b)
{
    a->next->prev = b;
    b->next = a->next;
    a->next = b;

    b->prev = a;
}

static inline void
list_head_insert_before(struct list_head *a, struct list_head *b)
{
    a->prev->next = b;
    b->prev = a->prev;
    a->prev = b;

    b->next = a;
}

#define ptr_offsetof(p,m) ((char*)(&(p)->m) - (char*)(p))
#define list_container(list,var,member) \
    ((void*)((char*)(list) - ptr_offsetof((var),member)))
#define LIST_FIRST_ENTRY(head,var,member)	\
    list_container((head)->next,var,member)
#define LIST_LAST_ENTRY(head,var,member)	\
    list_container((head)->prev,var,member)

#define LIST_NEXT_ENTRY(head,var,member)	\
    ((var)->member.next == head				\
     ? NULL : list_container((var)->member.next,var,member))
#define LIST_PREV_ENTRY(head,var,member)	\
    ((var)->member.prev == head				\
     ? NULL : list_container((var)->member.prev,var,member))

#define LIST_HEAD_INSERT_FIRST(head,var,member)	\
    list_head_insert_before((head)->next,&(var)->member)
#define LIST_HEAD_INSERT_LAST(head,var,member)	\
    list_head_insert_after((head)->prev,&(var)->member)

#define LIST_INSERT_AFTER(anchor,entry,member)	\
    list_head_insert_after(&(anchor)->member,&(entry)->member)
#define LIST_INSERT_BEFORE(anchor,entry,member)	\
    list_head_insert_before(&(anchor)->member,&(entry)->member)

#define LIST_REMOVE(entry,member)		\
    list_head_remove(&(entry)->member)

#define LIST_HEAD_POP(head,entry,member)	\
    (list_head_is_empty(head)				\
    ? NULL						\
    : (entry = LIST_FIRST_ENTRY(head, entry, member),	\
       LIST_REMOVE(entry, member), entry))
#define LIST_HEAD_PUSH(head,entry,member)	\
    LIST_HEAD_INSERT_FIRST(head,entry,member);

#define LIST_HEAD_ENQUEUE(head,var,member)	\
    LIST_HEAD_INSERT_LAST(head,var,member)
#define LIST_HEAD_DEQUEUE(head,var,member)	\
    LIST_HEAD_POP(head,var,member)

#define LIST_FOREACH_FROM(var,from,head,member)				\
    for (var = from;							\
         &(var)->member != (head);					\
	 var = list_container((var)->member.next,var,member))
#define LIST_FOREACH(var,head,member)					\
    LIST_FOREACH_FROM(var,LIST_FIRST_ENTRY(head,var,member),head,member)
#define LIST_FOREACH_FROM_SAFE(var,from,tmp,head,member)	        \
    for (var = from,							\
	     tmp = list_container((var)->member.next,tmp,member);	\
         &(var)->member != (head);					\
	 var = tmp,							\
	     tmp = list_container((var)->member.next,tmp,member))
#define LIST_FOREACH_SAFE(var,tmp,head,member)				\
    LIST_FOREACH_FROM_SAFE(var,LIST_FIRST_ENTRY(head,var,member),tmp,head,member)    

#define LIST_FOREACH_FROM_REVERSE(var,from,head,member)			\
    for (var = from;							\
         &(var)->member != (head);					\
	 var = list_container((var)->member.prev,var,member))
#define LIST_FOREACH_REVERSE(var,head,member)				\
    LIST_FOREACH_FROM_REVERSE(var,LIST_LAST_ENTRY(head,var,member),head,member)

#define LIST_FOREACH_FROM_REVERSE_SAFE(var,from,tmp,head,member)	\
    for (var = from,							\
	     tmp = list_container((var)->member.prev,tmp,member);	\
         &(var)->member != (head);					\
	 var = tmp,							\
	     tmp = list_container((var)->member.prev,tmp,member))
#define LIST_FOREACH_REVERSE_SAFE(var,tmp,head,member)			\
    LIST_FOREACH_FROM_REVERSE_SAFE(var,LIST_LAST_ENTRY(head,var,member),\
				   tmp,head,member)
