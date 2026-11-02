/*
 *----------------------------------------------------------------------
 *    micro T-Kernel 3.00.02
 *
 *    Copyright (C) 2006-2020 by Ken Sakamura.
 *    This software is distributed under the T-License 2.2.
 *----------------------------------------------------------------------
 *
 *    Released by TRON Forum(http://www.tron.org) at 2020/10/21 .
 *
 *----------------------------------------------------------------------
 */

/*
 *	memory.c
 *	In-kernel dynamic memory management
 */

#include "kernel.h"
#include "memory.h"
#include <sys/stack_diag.h>

/*
 * FreeQue search
 *	Search the free area whose size is equal to 'blksz',
 *	or larger than
 *      'blksz' but closest.
 *	If it does not exist, return '&imacb->freeque'.
 */
EXPORT QUEUE* knl_searchFreeArea( IMACB *imacb, W blksz )
{
	QUEUE	*q = &imacb->freeque;

	/* For area whose memory pool size is less than 1/4,
	   search from smaller size.
	   Otherwise, search from larger size. */
	if ( blksz > imacb->memsz / 4 ) {
		/* Search from larger size. */
		W fsz = 0;
		while ( (q = q->prev) != &imacb->freeque ) {
			fsz = FreeSize(q);
			if ( fsz <= blksz ) {
				return ( fsz < blksz )? q->next: q;
			}
		}
		return ( fsz >= blksz )? q->next: q;
	} else {
		/* Search from smaller size. */
		while ( (q = q->next) != &imacb->freeque ) {
			if ( FreeSize(q) >= blksz ) {
				break;
			}
		}
		return q;
	}
}


/*
 * Registration of free area on FreeQue
 *	FreeQue is composed of 2 types: Queue that links the
 *	different size of areas by size and queue that links the
 *	same size of areas.
 *
 *	freeque
 *	|
 *	|   +-----------------------+	    +-----------------------+
 *	|   | AreaQue		    |	    | AreaQue		    |
 *	|   +-----------------------+	    +-----------------------+
 *	*---> FreeQue Size order    |	    | EmptyQue		    |
 *	|   | FreeQue Same size   --------->| FreeQue Same size   ----->
 *	|   |			    |	    |			    |
 *	|   |			    |	    |			    |
 *	|   +-----------------------+	    +-----------------------+
 *	|   | AreaQue		    |	    | AreaQue		    |
 *	v   +-----------------------+	    +-----------------------+
 */
EXPORT void knl_appendFreeArea( IMACB *imacb, QUEUE *aq )
{
	QUEUE	*fq;
	W	size = AreaSize(aq);

	/* Registration position search */
	/*  Search the free area whose size is equal to 'blksz',
	 *  or larger than 'blksz' but closest.
	 *  If it does not exist, return '&imacb->freeque'.
	 */
	fq = knl_searchFreeArea(imacb, size);

	/* Register */
	clrAreaFlag(aq, AREA_USE);
	if ( fq != &imacb->freeque && FreeSize(fq) == size ) {
		/* FreeQue Same size */
		(aq + 2)->next = (fq + 1)->next;
		(fq + 1)->next = aq + 2;
		(aq + 2)->prev = fq + 1;
		if( (aq + 2)->next != NULL ) {
			(aq + 2)->next->prev = aq + 2;
		}
		(aq + 1)->next = NULL;
	} else {
		/* FreeQue Size order */
		QueInsert(aq + 1, fq);
		(aq + 2)->next = NULL;
		(aq + 2)->prev = (QUEUE*)size;
	}
}

/*
 * Delete from FreeQue
 */
EXPORT void knl_removeFreeQue( QUEUE *fq )
{
	if ( fq->next == NULL ) {	/* FreeQue Same size */
		(fq + 1)->prev->next = (fq + 1)->next;
		if ( (fq + 1)->next != NULL ) {
			(fq + 1)->next->prev = (fq + 1)->prev;
		}
	} else {			/* FreeQue Size order */
		if ( (fq + 1)->next != NULL ) {		/* having FreeQue Same size */
			QueInsert((fq + 1)->next - 1, fq);
			(fq + 1)->next->prev = (fq + 1)->prev;
		}
		QueRemove(fq);
	}
}

/*
 * Register area
 *	Insert 'ent' just after 'que.'
 */
EXPORT void knl_insertAreaQue( QUEUE *que, QUEUE *ent )
{
	ent->prev = que;
	ent->next = que->next;
	Assign(que->next->prev, ent);
	que->next = ent;
}

/*
 * Delete area
 */
EXPORT void knl_removeAreaQue( QUEUE *aq )
{
	Mask(aq->prev)->next = aq->next;
	Assign(aq->next->prev, Mask(aq->prev));
}

/* ------------------------------------------------------------------------ */

#if USE_IMALLOC
/* ------------------------------------------------------------------------ */

Noinit(EXPORT IMACB *knl_imacb);
LOCAL T_KHEAP heap_stats;

EXPORT ER knl_own_stack_stats(T_KSTACK *info)
{
#if USE_TASK_STACK_DIAG && defined(PICO_RP2040)
	UINT saved;
	TCB *self;
	volatile UB *base;
	SZ total;
	ID id;
	if (!info) return E_PAR;
	if (knl_get_ipsr() != 0) return E_CTX;
	DI(saved);
	self = knl_ctxtsk;
	/* The caller must allow interrupts during the potentially long scan. */
	if (isDI(saved) || !self || self->tskid <= 0 || self->sstksz <= 0 || !self->isstack) {
		EI(saved);
		return E_CTX;
	}
	if (self->tskatr & TA_USERBUF) {
		EI(saved);
		return E_NOSPT;
	}
	total = self->sstksz;
	base = (volatile UB *)self->isstack - total;
	id = self->tskid;
	EI(saved);
	/* This task owns its allocation throughout the scan. A local interrupt
	 * can lower the watermark during the scan; a later probe will see it.
	 * No kernel/global lock or interrupt mask is held across this walk. */
	SZ prefix = tk_stack_paint_prefix(base, total);
	info->task_id = id;
	info->total_bytes = (UW)total;
	info->paint_prefix = (UW)prefix;
	info->written_lower = (UW)(total - prefix);
	info->bottom_touched = prefix < 32;
	return E_OK;
#else
	(void)info;
	return E_NOSPT;
#endif
}

/* Same exclusion as the allocator. Current monitor heap writers and this
 * diagnostic reader all execute on physical core 0; this does not add global
 * SMP heap serialization for future callers on another core. */
EXPORT void knl_Imalloc_stats( T_KHEAP *info )
{
	UINT imask;
	if (info == NULL) return;
	DI(imask);
	*info = heap_stats;
	EI(imask);
}

LOCAL void allocation_failed( void )
{
	UINT imask;
	DI(imask);
	++heap_stats.allocation_failures;
	EI(imask);
}

/* ------------------------------------------------------------------------ */

/*
 * Memory allocate
 */
EXPORT void* knl_Imalloc( SZ size )
{
	QUEUE	*q, *aq, *aq2;
	UINT	imask;

	/* If it is smaller than the minimum fragment size,
	   allocate the minimum size to it. */
	if( size <= 0 || (UW)size > MAX_ALLOCATE ) {
		allocation_failed();
		return (void *)NULL;
	} else 	if ( size < MIN_FRAGMENT ) {
		size = MIN_FRAGMENT;
	} else {
		size = ROUND(size);
	}

	DI(imask);  /* Exclusive control by interrupt disable */

	/* Search FreeQue */
	q = knl_searchFreeArea(knl_imacb, size);
	if ( q == &(knl_imacb->freeque) ) {
		++heap_stats.allocation_failures;
		q = NULL; /* Insufficient memory */
		goto err_ret;
	}

	/* There is free area: Split from FreeQue once */
	knl_removeFreeQue(q);

	aq = q - 1;

	/* If there are fragments smaller than the minimum fragment size,
	   allocate them also */
	if ( FreeSize(q) - size >= MIN_FRAGMENT + sizeof(QUEUE) ) {

		/* Divide area into 2 */
		aq2 = (QUEUE*)((VB*)(aq + 1) + size);
		knl_insertAreaQue(aq, aq2);

		/* Register remaining area to FreeQue */
		knl_appendFreeArea(knl_imacb, aq2);
	}
	setAreaFlag(aq, AREA_USE);
	/* Count the actual span, including an unsplittable tail and header,
	 * rather than only the caller's requested byte count. */
	heap_stats.allocated_bytes += (UW)AreaSize(aq) + sizeof(QUEUE);
	++heap_stats.live_blocks;
	if (heap_stats.allocated_bytes > heap_stats.peak_allocated_bytes)
		heap_stats.peak_allocated_bytes = heap_stats.allocated_bytes;

err_ret:
	EI(imask);

	return (void *)q;
}

/*
 * Memory allocate  and clear
 */
EXPORT void* knl_Icalloc( SZ nmemb, SZ size )
{
	SZ	sz;
	void	*mem;
	/* Check before multiplying signed SZ: a wrapped count must never return
	 * a small allocation to a caller expecting a much larger array. */
	if (nmemb <= 0 || size <= 0 || (UW)nmemb > MAX_ALLOCATE / (UW)size) {
		allocation_failed();
		return NULL;
	}
	sz = nmemb * size;

	mem = knl_Imalloc(sz);
	if ( mem == NULL ) {
		return NULL;
	}

	knl_memset(mem, 0, sz);

	return mem;
}


/*
 * Memory allocation size change
 */
EXPORT void* knl_Irealloc( void *ptr, SZ size )
{
	void	*newptr;
	QUEUE	*aq;
	SZ	oldsz;

	if(size != 0) {
		newptr = knl_Imalloc(size);
		if(newptr == NULL) {
			return NULL;
		}
	} else {
		newptr = NULL;
	}

	if(ptr != NULL) {
		if(newptr != NULL) {
			aq = (QUEUE*)ptr - 1;
			oldsz = (SZ)AreaSize(aq);
			knl_memcpy(newptr, ptr, (size > oldsz)?oldsz:size);
		}
		knl_Ifree(ptr);
	}

	return newptr;
}


/*
 * Free memory
 */
EXPORT void  knl_Ifree( void *ptr )
{
	QUEUE	*aq;
	UINT	imask;
	if (ptr == NULL) return;

	DI(imask);  /* Exclusive control by interrupt disable */

	aq = (QUEUE*)ptr - 1;
	heap_stats.allocated_bytes -= (UW)AreaSize(aq) + sizeof(QUEUE);
	--heap_stats.live_blocks;
	clrAreaFlag(aq, AREA_USE);

	if ( !chkAreaFlag(aq->next, AREA_USE) ) {
		/* Merge with free area in after location */
		knl_removeFreeQue(aq->next + 1);
		knl_removeAreaQue(aq->next);
	}

	if ( !chkAreaFlag(aq->prev, AREA_USE) ) {
		/* Merge with free area in front location */
		aq = aq->prev;
		knl_removeFreeQue(aq + 1);
		knl_removeAreaQue(aq->next);
	}

	knl_appendFreeArea(knl_imacb, aq);

	EI(imask);
}


/* ------------------------------------------------------------------------ */

/*
 * IMACB Initialization 
 */
LOCAL void initIMACB( void )
{
	QueInit(&(knl_imacb->areaque));
	QueInit(&(knl_imacb->freeque));
}

/*
 * Imalloc initial setting 
 */
EXPORT ER knl_init_Imalloc( void )
{
	QUEUE	*top, *end;
	knl_memset(&heap_stats, 0, sizeof(heap_stats));

	/* Align top with 4 byte unit alignment for IMACB */
	knl_lowmem_top = (void *)(((UW)knl_lowmem_top + 3) & ~0x00000003UL);
	knl_imacb = (IMACB*)knl_lowmem_top;
	knl_lowmem_top = (void *)((UW)knl_lowmem_top + sizeof(IMACB));

	/* Align top with 8 byte unit alignment */
	knl_lowmem_top = (void *)(((UW)knl_lowmem_top + 7) & ~0x00000007UL);
	top = (QUEUE*)knl_lowmem_top;
	knl_imacb->memsz = (W)((UW)knl_lowmem_limit - (UW)knl_lowmem_top - sizeof(QUEUE)*2);

	knl_lowmem_top = knl_lowmem_limit;  /* Update memory free space */

	initIMACB();

	/* Register on AreaQue */
	end = (QUEUE*)((VB*)top + knl_imacb->memsz) + 1;
	knl_insertAreaQue(&knl_imacb->areaque, end);
	knl_insertAreaQue(&knl_imacb->areaque, top);
	setAreaFlag(end, AREA_USE);
	setAreaFlag(&knl_imacb->areaque, AREA_USE);

	knl_appendFreeArea(knl_imacb, top);

	return E_OK;
}

#endif /* USE_IMALLOC */
