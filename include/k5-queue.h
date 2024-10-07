/*
 * This is a copy of NetBSD's sys/queue.h, edited to use a different symbol for
 * multiple inclusion protection and to suppress the include of <sys/null.h>.
 */

/*	$NetBSD: queue.h,v 1.53 2011/11/19 22:51:31 tls Exp $	*/


#ifndef	K5_QUEUE_H
#define	K5_QUEUE_H

/* #include <sys/null.h> */

/*
 * List definitions.
 */
#define	K5_LIST_HEAD(name, type)					\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define	K5_LIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	K5_LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

/*
 * List functions.
 */
#define	K5_LIST_INIT(head) do {						\
	(head)->lh_first = NULL;					\
} while (/*CONSTCOND*/0)

#define	K5_LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} while (/*CONSTCOND*/0)

#define	K5_LIST_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	(elm)->field.le_next = (listelm);				\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &(elm)->field.le_next;		\
} while (/*CONSTCOND*/0)

#define	K5_LIST_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (/*CONSTCOND*/0)

#define	K5_LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev = 			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
} while (/*CONSTCOND*/0)

#define	K5_LIST_FOREACH(var, head, field)				\
	for ((var) = ((head)->lh_first);				\
		(var);							\
		(var) = ((var)->field.le_next))

#define	K5_LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = K5_LIST_FIRST((head));				\
		(var) && ((tvar) = K5_LIST_NEXT((var), field), 1);	\
		(var) = (tvar))
/*
 * List access methods.
 */
#define	K5_LIST_EMPTY(head)		((head)->lh_first == NULL)
#define	K5_LIST_FIRST(head)		((head)->lh_first)
#define	K5_LIST_NEXT(elm, field)	((elm)->field.le_next)


/*
 * Singly-linked List definitions.
 */
#define	K5_SLIST_HEAD(name, type)					\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	K5_SLIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define	K5_SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

/*
 * Singly-linked List functions.
 */
#define	K5_SLIST_INIT(head) do {					\
	(head)->slh_first = NULL;					\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_INSERT_AFTER(slistelm, elm, field) do {		\
	(elm)->field.sle_next = (slistelm)->field.sle_next;		\
	(slistelm)->field.sle_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_REMOVE_HEAD(head, field) do {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		K5_SLIST_REMOVE_HEAD((head), field);			\
	}								\
	else {								\
		struct type *curelm = (head)->slh_first;		\
		while(curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_REMOVE_AFTER(slistelm, field) do {			\
	(slistelm)->field.sle_next =					\
	    K5_SLIST_NEXT(K5_SLIST_NEXT((slistelm), field), field);	\
} while (/*CONSTCOND*/0)

#define	K5_SLIST_FOREACH(var, head, field)				\
	for((var) = (head)->slh_first; (var); (var) = (var)->field.sle_next)

#define	K5_SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = K5_SLIST_FIRST((head));				\
	    (var) && ((tvar) = K5_SLIST_NEXT((var), field), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List access methods.
 */
#define	K5_SLIST_EMPTY(head)	((head)->slh_first == NULL)
#define	K5_SLIST_FIRST(head)	((head)->slh_first)
#define	K5_SLIST_NEXT(elm, field)	((elm)->field.sle_next)


/*
 * Singly-linked Tail queue declarations.
 */
#define	K5_STAILQ_HEAD(name, type)					\
struct name {								\
	struct type *stqh_first;	/* first element */			\
	struct type **stqh_last;	/* addr of last next element */		\
}

#define	K5_STAILQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).stqh_first }

#define	K5_STAILQ_ENTRY(type)						\
struct {								\
	struct type *stqe_next;	/* next element */			\
}

/*
 * Singly-linked Tail queue functions.
 */
#define	K5_STAILQ_INIT(head) do {					\
	(head)->stqh_first = NULL;					\
	(head)->stqh_last = &(head)->stqh_first;				\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.stqe_next = (head)->stqh_first) == NULL)	\
		(head)->stqh_last = &(elm)->field.stqe_next;		\
	(head)->stqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.stqe_next = NULL;					\
	*(head)->stqh_last = (elm);					\
	(head)->stqh_last = &(elm)->field.stqe_next;			\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.stqe_next = (listelm)->field.stqe_next) == NULL)\
		(head)->stqh_last = &(elm)->field.stqe_next;		\
	(listelm)->field.stqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_REMOVE_HEAD(head, field) do {				\
	if (((head)->stqh_first = (head)->stqh_first->field.stqe_next) == NULL) \
		(head)->stqh_last = &(head)->stqh_first;			\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_REMOVE(head, elm, type, field) do {			\
	if ((head)->stqh_first == (elm)) {				\
		K5_STAILQ_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->stqh_first;		\
		while (curelm->field.stqe_next != (elm))		\
			curelm = curelm->field.stqe_next;		\
		if ((curelm->field.stqe_next =				\
			curelm->field.stqe_next->field.stqe_next) == NULL) \
			    (head)->stqh_last = &(curelm)->field.stqe_next; \
	}								\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->stqh_first);				\
		(var);							\
		(var) = ((var)->field.stqe_next))

#define	K5_STAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = K5_STAILQ_FIRST((head));				\
	    (var) && ((tvar) = K5_STAILQ_NEXT((var), field), 1);	\
	    (var) = (tvar))

#define	K5_STAILQ_CONCAT(head1, head2) do {				\
	if (!K5_STAILQ_EMPTY((head2))) {				\
		*(head1)->stqh_last = (head2)->stqh_first;		\
		(head1)->stqh_last = (head2)->stqh_last;		\
		K5_STAILQ_INIT((head2));				\
	}								\
} while (/*CONSTCOND*/0)

#define	K5_STAILQ_LAST(head, type, field)				\
	(K5_STAILQ_EMPTY((head)) ?					\
		NULL :							\
	        ((struct type *)(void *)				\
		((char *)((head)->stqh_last) - offsetof(struct type, field))))

/*
 * Singly-linked Tail queue access methods.
 */
#define	K5_STAILQ_EMPTY(head)	((head)->stqh_first == NULL)
#define	K5_STAILQ_FIRST(head)	((head)->stqh_first)
#define	K5_STAILQ_NEXT(elm, field)	((elm)->field.stqe_next)


/*
 * Simple queue definitions.
 */
#define	K5_SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;	/* first element */			\
	struct type **sqh_last;	/* addr of last next element */		\
}

#define	K5_SIMPLEQ_HEAD_INITIALIZER(head)				\
	{ NULL, &(head).sqh_first }

#define	K5_SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;	/* next element */			\
}

/*
 * Simple queue functions.
 */
#define	K5_SIMPLEQ_INIT(head) do {					\
	(head)->sqh_first = NULL;					\
	(head)->sqh_last = &(head)->sqh_first;				\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqe_next = NULL;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_REMOVE_HEAD(head, field) do {			\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_REMOVE(head, elm, type, field) do {			\
	if ((head)->sqh_first == (elm)) {				\
		K5_SIMPLEQ_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->sqh_first;		\
		while (curelm->field.sqe_next != (elm))			\
			curelm = curelm->field.sqe_next;		\
		if ((curelm->field.sqe_next =				\
			curelm->field.sqe_next->field.sqe_next) == NULL) \
			    (head)->sqh_last = &(curelm)->field.sqe_next; \
	}								\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->sqh_first);				\
		(var);							\
		(var) = ((var)->field.sqe_next))

#define	K5_SIMPLEQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = ((head)->sqh_first);				\
		(var) && ((next = ((var)->field.sqe_next)), 1);		\
		(var) = (next))

#define	K5_SIMPLEQ_CONCAT(head1, head2) do {				\
	if (!K5_SIMPLEQ_EMPTY((head2))) {				\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;		\
		K5_SIMPLEQ_INIT((head2));				\
	}								\
} while (/*CONSTCOND*/0)

#define	K5_SIMPLEQ_LAST(head, type, field)				\
	(K5_SIMPLEQ_EMPTY((head)) ?					\
		NULL :							\
	        ((struct type *)(void *)				\
		((char *)((head)->sqh_last) - offsetof(struct type, field))))

/*
 * Simple queue access methods.
 */
#define	K5_SIMPLEQ_EMPTY(head)		((head)->sqh_first == NULL)
#define	K5_SIMPLEQ_FIRST(head)		((head)->sqh_first)
#define	K5_SIMPLEQ_NEXT(elm, field)	((elm)->field.sqe_next)


/*
 * Tail queue definitions.
 */
#define	_K5_TAILQ_HEAD(name, type, qual)				\
struct name {								\
	qual type *tqh_first;		/* first element */		\
	qual type *qual *tqh_last;	/* addr of last next element */	\
}
#define K5_TAILQ_HEAD(name, type)	_K5_TAILQ_HEAD(name, struct type,)

#define	K5_TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define	_K5_TAILQ_ENTRY(type, qual)					\
struct {								\
	qual type *tqe_next;		/* next element */		\
	qual type *qual *tqe_prev;	/* address of previous next element */\
}
#define K5_TAILQ_ENTRY(type)	_K5_TAILQ_ENTRY(struct type,)

/*
 * Tail queue functions.
 */
#define	K5_TAILQ_INIT(head) do {					\
	(head)->tqh_first = NULL;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev = 		\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_INSERT_BEFORE(listelm, elm, field) do {		\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev = 		\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
} while (/*CONSTCOND*/0)

#define	K5_TAILQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->tqh_first);				\
		(var);							\
		(var) = ((var)->field.tqe_next))

#define	K5_TAILQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = ((head)->tqh_first);				\
	        (var) != NULL && ((next) = K5_TAILQ_NEXT(var, field), 1);	\
		(var) = (next))

#define	K5_TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for ((var) = (*(((struct headname *)((head)->tqh_last))->tqh_last));	\
		(var);							\
		(var) = (*(((struct headname *)((var)->field.tqe_prev))->tqh_last)))

#define	K5_TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, prev)	\
	for ((var) = K5_TAILQ_LAST((head), headname);			\
		(var) && ((prev) = K5_TAILQ_PREV((var), headname, field), 1);\
		(var) = (prev))

#define	K5_TAILQ_CONCAT(head1, head2, field) do {			\
	if (!K5_TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		K5_TAILQ_INIT((head2));					\
	}								\
} while (/*CONSTCOND*/0)

/*
 * Tail queue access methods.
 */
#define	K5_TAILQ_EMPTY(head)		((head)->tqh_first == NULL)
#define	K5_TAILQ_FIRST(head)		((head)->tqh_first)
#define	K5_TAILQ_NEXT(elm, field)	((elm)->field.tqe_next)

#define	K5_TAILQ_LAST(head, headname) \
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
#define	K5_TAILQ_PREV(elm, headname, field) \
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))


/*
 * Circular queue definitions.
 */
#define	K5_CIRCLEQ_HEAD(name, type)					\
struct name {								\
	struct type *cqh_first;		/* first element */		\
	struct type *cqh_last;		/* last element */		\
}

#define	K5_CIRCLEQ_HEAD_INITIALIZER(head)				\
	{ (void *)&head, (void *)&head }

#define	K5_CIRCLEQ_ENTRY(type)						\
struct {								\
	struct type *cqe_next;		/* next element */		\
	struct type *cqe_prev;		/* previous element */		\
}

/*
 * Circular queue functions.
 */
#define	K5_CIRCLEQ_INIT(head) do {					\
	(head)->cqh_first = (void *)(head);				\
	(head)->cqh_last = (void *)(head);				\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.cqe_next = (listelm)->field.cqe_next;		\
	(elm)->field.cqe_prev = (listelm);				\
	if ((listelm)->field.cqe_next == (void *)(head))		\
		(head)->cqh_last = (elm);				\
	else								\
		(listelm)->field.cqe_next->field.cqe_prev = (elm);	\
	(listelm)->field.cqe_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_INSERT_BEFORE(head, listelm, elm, field) do {	\
	(elm)->field.cqe_next = (listelm);				\
	(elm)->field.cqe_prev = (listelm)->field.cqe_prev;		\
	if ((listelm)->field.cqe_prev == (void *)(head))		\
		(head)->cqh_first = (elm);				\
	else								\
		(listelm)->field.cqe_prev->field.cqe_next = (elm);	\
	(listelm)->field.cqe_prev = (elm);				\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.cqe_next = (head)->cqh_first;			\
	(elm)->field.cqe_prev = (void *)(head);				\
	if ((head)->cqh_last == (void *)(head))				\
		(head)->cqh_last = (elm);				\
	else								\
		(head)->cqh_first->field.cqe_prev = (elm);		\
	(head)->cqh_first = (elm);					\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.cqe_next = (void *)(head);				\
	(elm)->field.cqe_prev = (head)->cqh_last;			\
	if ((head)->cqh_first == (void *)(head))			\
		(head)->cqh_first = (elm);				\
	else								\
		(head)->cqh_last->field.cqe_next = (elm);		\
	(head)->cqh_last = (elm);					\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_REMOVE(head, elm, field) do {			\
	if ((elm)->field.cqe_next == (void *)(head))			\
		(head)->cqh_last = (elm)->field.cqe_prev;		\
	else								\
		(elm)->field.cqe_next->field.cqe_prev =			\
		    (elm)->field.cqe_prev;				\
	if ((elm)->field.cqe_prev == (void *)(head))			\
		(head)->cqh_first = (elm)->field.cqe_next;		\
	else								\
		(elm)->field.cqe_prev->field.cqe_next =			\
		    (elm)->field.cqe_next;				\
} while (/*CONSTCOND*/0)

#define	K5_CIRCLEQ_FOREACH(var, head, field)				\
	for ((var) = ((head)->cqh_first);				\
		(var) != (const void *)(head);				\
		(var) = ((var)->field.cqe_next))

#define	K5_CIRCLEQ_FOREACH_REVERSE(var, head, field)			\
	for ((var) = ((head)->cqh_last);				\
		(var) != (const void *)(head);				\
		(var) = ((var)->field.cqe_prev))

/*
 * Circular queue access methods.
 */
#define	K5_CIRCLEQ_EMPTY(head)		((head)->cqh_first == (void *)(head))
#define	K5_CIRCLEQ_FIRST(head)		((head)->cqh_first)
#define	K5_CIRCLEQ_LAST(head)		((head)->cqh_last)
#define	K5_CIRCLEQ_NEXT(elm, field)	((elm)->field.cqe_next)
#define	K5_CIRCLEQ_PREV(elm, field)	((elm)->field.cqe_prev)

#define K5_CIRCLEQ_LOOP_NEXT(head, elm, field)				\
	(((elm)->field.cqe_next == (void *)(head))			\
	    ? ((head)->cqh_first)					\
	    : (elm->field.cqe_next))
#define K5_CIRCLEQ_LOOP_PREV(head, elm, field)				\
	(((elm)->field.cqe_prev == (void *)(head))			\
	    ? ((head)->cqh_last)					\
	    : (elm->field.cqe_prev))

#endif	/* !K5_QUEUE_H */
