
//	Author Karl Malbrain, malbrain@yahoo.com

//	Implement Simplified HAT-trie w/associated data areas,
//	and bi-directional cursors

//	Adapted from the ideas of Douglas Baskins of HP
//	and Dr. Askitis.

//	The ASKITIS benchmarking option was implemented with 
//	assistance from Dr. Nikolas Askitis (www.naskitis.com). 

//	functions:
//	hat_open:	open a new hat array returning a hat object.
//	hat_close:	close an open hat array, freeing all memory.
//	hat_data:	allocate data memory within hat array for external use.
//	hat_cell:	insert a string into the HAT tree, return associated data addr.
//	hat_cursor:	return a sort cursor for the HAT tree. Free with free().
//	hat_key:	return the key from the HAT trie at the current cursor location.
//	hat_nxt:	move the cursor to the next key in the HAT trie, return TRUE/FALSE.
//	hat_prv:	move the cursor to the prev key in the HAT trie, return TRUE/FALSE.
//	hat_start:	move the cursor to the first key >= given key, return TRUE/FALSE.
//	hat_last:	move the cursor to the last key in the HAT trie, return TRUE/FALSE
//	hat_slot:	return the pointer to the associated data area for cursor.

#ifdef linux
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define __USE_FILE_OFFSET64

//#include <endian.h>
#else
#ifdef __BIG_ENDIAN__
#ifndef BYTE_ORDER
#define BYTE_ORDER 4321
#endif
#else
#ifndef BYTE_ORDER
#define BYTE_ORDER 1234
#endif
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif
#endif

#if 0
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#endif

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/bitops.h>
#include <linux/cryptohash.h>
#include <asm/unaligned.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/types.h>

#include "hattrie.h"

#if defined(_WIN32)
typedef unsigned short ushort;
#endif

#if defined(__LP64__) ||						\
	defined(__x86_64__) ||						\
	defined(__amd64__) ||						\
	defined(_WIN64) ||							\
	defined(__sparc64__) ||						\
	defined(__arch64__) ||						\
	defined(__powerpc64__) ||					\
	defined (__s390x__) 
//	defines for 64 bit
	
typedef unsigned long long HatSlot;
#define HAT_slot_size 8

#define PRIhatvalue	"llu"

#else
//	defines for 32 bit
	
typedef uint HatSlot;
#define HAT_slot_size 4

#define PRIhatvalue	"u"

#endif

#define HAT_mask (~(HatSlot)0x07)
#define HAT_type ((HatSlot)0x07)

#define HAT_node_size	16

typedef struct {
	HatSlot array[0];	// hash array of pail arrays
} HatPail;

typedef struct {
	uint count;
	HatSlot slots[0];
} HatBucket;

#define HAT_cache_line 8	// allocation granularity is 8 bytes

#if 0
#include <assert.h>
#include <stdio.h>
#endif

unsigned long long MaxMem = 0;
unsigned long long Searches = 0;
unsigned long long Probes = 0;
unsigned long long Bucket = 0;
unsigned long long Pail = 0;
unsigned long long Radix = 0;
unsigned long long Small = 0;

// void hat_abort (char *msg) __attribute__ ((noreturn)); // Tell static analyser that this function will not return
void hat_abort (char *msg)
{
	printk(KERN_ALERT "%s\n", msg);
	BUG();
}

//	allow room for 64K bucket slots and HatSeg structure

#define HAT_seg	(65536 * HAT_slot_size + 32)

enum HAT_types {
	HAT_radix		= 0,	// radix nodes
	HAT_bucket		= 1,	// bucket nodes
	HAT_array		= 2,	// linear array nodes
	HAT_pail		= 3,	// hashed linear array nodes
	HAT_1			= 4,
	HAT_2			= 5,
	HAT_3			= 6,
	HAT_4			= 7,
	HAT_6			= 8,
	HAT_8			= 9,
	HAT_10			= 10,
	HAT_12			= 11,
	HAT_14			= 12,
	HAT_16			= 13,
	HAT_24			= 14,
	HAT_32			= 15,
};

uint HatSize[32] = {
	(HAT_slot_size * 128),	// HAT_radix node size
	(sizeof(HatBucket)),	// HAT_bucket node size
	(0),					// HAT_array node size below
	(sizeof(HatPail)),		// HAT_pail node size
	(1 * HAT_node_size),	// HAT_1 array size
	(2 * HAT_node_size),	// HAT_2 array size
	(3 * HAT_node_size),	// HAT_3 array size
	(4 * HAT_node_size),	// HAT_4 array size
	(6 * HAT_node_size),	// HAT_6 array size
	(8 * HAT_node_size),	// HAT_8 array size
	(10 * HAT_node_size),	// HAT_10 array size
	(12 * HAT_node_size),	// HAT_12 array size
	(14 * HAT_node_size),	// HAT_14 array size
	(16 * HAT_node_size),	// HAT_16 array size
	(24 * HAT_node_size),	// HAT_24 array size
	(32 * HAT_node_size),	// HAT_32 array size
};

uint HatBucketSlots = 2047;
uint HatBucketMax = 65536;
uint HatPailMax = 127;

uchar HatMax = HAT_32;

typedef struct {
	void *seg;			// next used allocator
	uint next;			// next available offset
} HatSeg;

typedef struct Hat {
	void **reuse[32];	// reuse hat blocks
	int counts[32];		// hat block counters
	HatSeg *seg;		// current hat allocator
	uint bootlvl;		// cascaded radix nodes in root
	uint aux;			// auxiliary bytes per key
	HatSlot root[0];	// base root of hat array
} Hat;

typedef struct {
	ushort nxt;			// next key array allocation
	uchar type;			// type of base node
	uchar cnt;			// next data area allocation
	uchar keys[0];		// keys byte array
} HatBase;

typedef struct {
	uchar *key;			// pointer to key string
	void *slot;			// user data area
} HatSort;

typedef struct HatCursor {
	int cnt;			// number of bucket keys
	int idx;			// current bucket index
	short top;			// current stack top
	ushort aux;			// number of aux bytes per key
	int rootlvl;		// number of root levels
	uint maxroot;		// count of root array slots
	uint rootscan;		// triple root scan index
	HatSlot next[256];	// radix node stack
	uchar scan[256];	// radix node scan index stack
	HatSort keys[0];	// sorted array for bucket
} HatCursor;

int hat_nxt (HatCursor *cursor);

//	ternery quick sort of cursor's keys
//	modelled after R Sedgewick's
//	"Quicksort with 3-way partitioning"

#define malloc(x)								\
	kmalloc((x), GFP_KERNEL)

#define free(x)									\
	kfree(x)

static int rand(void)
{
	int ret;
	get_random_bytes(&ret, sizeof(ret));
	return ret;
}

vecswap (int i, int j, int n, HatSort *x)
{
	HatSort swap[1];

	while( n-- ) {
		*swap = x[i];
		x[i++] = x[j];
		x[j++] = *swap;
	}	
}

void hat_qsort (HatSort *x, int n, uchar o)
{
	ushort skip, skipb, skipc, len;
	uchar pivot, chb, chc, *key;
	int a, b, c, d, r;
	HatSort swap[1];

	while( n > 10 ) {
		a = rand () % n;

		*swap = x[0];
		x[0] = x[a];
		x[a] = *swap;

		len = x[0].key[0];

		if( len & 0x80 )
			len &= 0x7f, len += x[0].key[1], skip = 2;
		else
			skip = 1;

		if( len > o )
			pivot = x[0].key[o+skip];
		else
			pivot = 0;

		a = b = 1;
		c = d = n - 1;

		while( 1 ) {
			while( b <= c ) {
				len = x[b].key[0];

				if( len & 0x80 )
					len &= 0x7f, len += x[b].key[1], skip = 2;
				else
					skip = 1;

				if( len > o )
					chb = x[b].key[o+skip];
				else
					chb = 0;
				if( chb > pivot )
					break;
				if( chb == pivot ) {
					*swap = x[a];
					x[a++] = x[b];
					x[b] = *swap;
				}
				b += 1;
			}

			while( b <= c ) {
				len = x[c].key[0];

				if( len & 0x80 )
					len &= 0x7f, len += x[c].key[1], skip = 2;
				else
					skip = 1;

				if( len > o )
					chc = x[c].key[o+skip];
				else
					chc = 0;
				if( chc < pivot )
					break;
				if( chc == pivot ) {
					*swap = x[c];
					x[c] = x[d];
					x[d--] = *swap;
				}
				c -= 1;
			}

			if( b > c )
				break;

			*swap = x[b];
			x[b++] = x[c];
			x[c--] = *swap;
		}

		r = a < b-a ? a : b-a;
		vecswap (0, b-r, r, x);

		r = d-c < n-d-1 ? d-c : n-d-1;
		vecswap (b, n-r, r, x);

		if( r = d - c )
			hat_qsort (x + n - r, r, o);

		if( r = b - a )
			hat_qsort (x, r, o);

		len = x[r].key[0];

		if( len & 0x80 )
			len &= 0x7f, len += x[r].key[1];

		if( len == o )
			return;

		n += a - d - 1;
		x += r;
		o += 1;
	}

	if( n > 1 ) {
		a = 0;

		while( ++a < n )
			for( b = a; b > 0; b-- ) {
				chb = x[b-1].key[0];
				if( chb & 0x80 )
					chb &= 0x7f, chb += x[b-1].key[1], skipb = 2;
				else
					skipb = 1;
				chc = x[b].key[0];
				if( chc & 0x80 )
					chc &= 0x7f, chc += x[b].key[1], skipc = 2;
				else
					skipc = 1;
				r = o;
				d = 0;

				while( r < chb && r < chc )
					if( d = x[b-1].key[r+skipb] - x[b].key[r+skipc] )
						break;
					else
						r++;

				if( d > 0 || d == 0 && chb > chc ) {
					*swap = x[b];
					x[b] = x[b-1];
					x[b-1] = *swap;
				}
			}
	}
}

//	strip out pointers from HAT_array node
//	to elements of the sorted array

int hat_strip_array (HatCursor *cursor, HatSlot node, HatSort *list)
{
	HatBase *base = (HatBase *)(node & HAT_mask);
	uint size = HatSize[base->type];
	ushort tst = 0;
	ushort cnt = 0;
	ushort len;

	while( tst < base->nxt ) {
		list[cnt].slot = (uchar *)base + size - (cnt+1) * cursor->aux;
		list[cnt].key = base->keys + tst;
		len = base->keys[tst++];
		if( len & 0x80 )
			len &= 0x7f, len += base->keys[tst++] << 7;
		tst += len;
		cnt++;
	}

	return cnt;
}

int hat_strip_pail (HatCursor *cursor, HatSlot node, HatSort *list)
{
	HatPail *pail = (HatPail *)(node & HAT_mask);
	uint total = 0;
	int idx;

	for( idx = 0; idx < HatPailMax; idx++ )
		if( pail->array[idx] )
			total += hat_strip_array (cursor, pail->array[idx], list);

	return total;
}

//	sort current bucket into cursor array

//	find and sort current node entry
//  either Bucket or Array


void hat_sort (HatCursor *cursor)
{
	HatBucket *bucket;
	uint off, idx;
	uchar len, ch;
	uint cnt;

	switch( cursor->next[cursor->top] & HAT_type ) {
	case HAT_array:
		cursor->cnt = hat_strip_array (cursor, cursor->next[cursor->top], cursor->keys);
		break;

	case HAT_pail:
		cursor->cnt = hat_strip_pail (cursor, cursor->next[cursor->top], cursor->keys);
		break;

	case HAT_bucket:
		bucket = (HatBucket *)(cursor->next[cursor->top] & HAT_mask);
		cursor->cnt = 0;

		for( idx = 0; idx < HatBucketSlots; idx++ )
			switch( bucket->slots[idx] & HAT_type ) {
			case HAT_array:
				cursor->cnt += hat_strip_array (cursor, bucket->slots[idx], cursor->keys + cursor->cnt);
				continue;
			case HAT_pail:
				cursor->cnt += hat_strip_pail (cursor, bucket->slots[idx], cursor->keys + cursor->cnt);
				continue;
			}

		break;

	}

	hat_qsort (cursor->keys, cursor->cnt, 0);
}

int hat_greater (HatCursor *cursor, uchar *buff, uint max)
{
	uchar len;

	//	find first key >= given key

	for( cursor->idx = 0; cursor->idx < cursor->cnt; cursor->idx++ ) {
		len = cursor->keys[cursor->idx].key[0];
		if( memcmp (cursor->keys[cursor->idx].key + 1, buff, len > max ? max : len) )
			continue;
		if( len >= max )
			return 1;
	}

	//	given key > every key in bucket

	return hat_nxt (cursor);
}

//	open new sort cursor into collection

void *hat_cursor (Hat *hat)
{
	HatCursor *cursor;
	uint size;

	size = sizeof(HatCursor) + HatBucketMax * sizeof(HatSort);
	cursor = malloc (size);
	memset (cursor, 0, size);

	cursor->next[0] = (HatSlot)hat->root;
	cursor->aux = hat->aux;
	cursor->maxroot = 1;

	for( cursor->rootlvl = 0; cursor->rootlvl < hat->bootlvl; cursor->rootlvl++ )
		cursor->maxroot *= 128;

	return cursor;
}

void *hat_start (HatCursor *cursor, uchar *buff, uint max)
{
	HatSlot *radix, *root;
	HatSlot next;
	uint off = 0;
	uint idx;
	uchar ch;

	if( max > 255 )
		max = 255;

	for( idx = 0; idx < cursor->rootlvl; idx++ ) {
		cursor->rootscan *= 128;
		if( off < max )
			cursor->rootscan += buff[off++];
	}

	//	find first root >= given key

	root = (HatSlot *)(cursor->next[0]);
	cursor->top = 0;

	if( next = root[cursor->rootscan] ) {
		cursor->next[++cursor->top] = next;

	loop:
		if( (cursor->next[cursor->top] & HAT_type) == HAT_radix ) {
			if( max > off )
				ch = buff[off++];
			else
				ch = 0;

			radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);

			while( ch < 128 )
				if( radix[ch] ) {
					cursor->scan[cursor->top] = ch;
					cursor->next[++cursor->top] = radix[ch];
					goto loop;
				} else
					max = 0, ch++;

			//	given key > every key

			if( hat_nxt (cursor) )
				return cursor;

			free (cursor);
			return NULL;
		}

		hat_sort (cursor);
		cursor->idx = 0;

		if( hat_greater (cursor, buff + off, max - off) )
			return cursor;

		free (cursor);
		return NULL;
	}

	//	scan to next occupied root

	cursor->top++;

	if( hat_nxt (cursor) )
		return cursor;

	free (cursor);
	return NULL;
}

//	return user area slot address at given cursor location

void *hat_slot (HatCursor *cursor)
{
	return cursor->keys[cursor->idx].slot;
}

//	advance cursor to next key
//	returning false if EOT

int hat_nxt (HatCursor *cursor)
{
	HatSlot *radix;
	uint idx, max;
	uchar ch;

	//  any keys left in current sorted array?

	if( ++cursor->idx < cursor->cnt )
		return 1;

	//  move thru radix nodes
	//	slot zero is the triple root

	while( --cursor->top >= 0 ) {
		radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);

		if( !cursor->top )
			max = cursor->maxroot;
		else
			max = 128;

		if( cursor->top )
			idx = cursor->scan[cursor->top];
		else
			idx = cursor->rootscan;

		while( ++idx < max )
			if( radix[idx] ) {
				if( cursor->top )
					cursor->scan[cursor->top] = idx;
				else
					cursor->rootscan = idx;

				cursor->next[++cursor->top] = radix[idx];
			loop:
				if( (cursor->next[cursor->top] & HAT_type) == HAT_radix ) {
					radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);

					for( ch = 0; ch < 128; ch++ )
						if( radix[ch] ) {
							cursor->scan[cursor->top] = ch;
							cursor->next[++cursor->top] = radix[ch];
							goto loop;
						}
				}

				hat_sort (cursor);
				cursor->idx = 0;
				return 1;
			}
	}

	return 0;
}

//	advance cursor to previous key
//	returning false if BOI

int hat_prv (HatCursor *cursor)
{
	HatSlot *radix;
	uint idx, max;
	uchar ch;

	//  any keys left in current sorted array?

	if( cursor->idx )
		return cursor->idx--, 1;

	//  move down thru radix nodes
	//	slot zero is the triple root

	while( --cursor->top >= 0 ) {
		radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);

		if( cursor->top )
			idx = cursor->scan[cursor->top];
		else
			idx = cursor->rootscan;

		while( idx-- )
			if( radix[idx] ) {
				if( cursor->top )
					cursor->scan[cursor->top] = idx;
				else
					cursor->rootscan = idx;

				cursor->next[++cursor->top] = radix[idx];
			loop:
				if( (cursor->next[cursor->top] & HAT_type) == HAT_radix ) {
					radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);

					for( ch = 128; ch-- > 0; )
						if( radix[ch] ) {
							cursor->scan[cursor->top] = ch;
							cursor->next[++cursor->top] = radix[ch];
							goto loop;
						}
				}

				hat_sort (cursor);
				cursor->idx = cursor->cnt - 1;
				return 1;
			}
	}

	return 0;
}

//	advance cursor to last key in the trie
//	returning false if tree is empty

int hat_last (HatCursor *cursor)
{
	HatSlot *radix, next, *root;
	uint idx, max;
	uchar ch;

	//	find last root
	//	or return if tree is empty

	cursor->rootscan = cursor->maxroot;
	root = (HatSlot *)(cursor->next[0]);
	cursor->top = 0;

	while( cursor->rootscan )
		if( next = root[--cursor->rootscan] )
			break;
		else if( !cursor->rootscan )
			return 0;
	  
	cursor->next[++cursor->top] = next;

loop:
	if( (cursor->next[cursor->top] & HAT_type) == HAT_radix ) {
		radix = (HatSlot *)(cursor->next[cursor->top] & HAT_mask);
		ch = 128;

		while( ch-- )
			if( radix[ch] ) {
				cursor->scan[cursor->top] = ch;
				cursor->next[++cursor->top] = radix[ch];
				goto loop;
			}
	}

	hat_sort (cursor);
  	cursor->idx = cursor->cnt - 1;
	return 1;
}

//	return key at current cursor location

uint hat_key (HatCursor *cursor, uchar *buff, uint max)
{
	int idx, scan, len;
	uchar *key, ch;
	uint off = 0;

	max--;	// leave room for terminator

	//	is cursor at EOF?

	if( cursor->top < 0 ) {
		if( max )
			buff[0] = 0;
		return 0;
	}

	//	fill in from triple root
	//	and cascaded radix nodes

	for( idx = 0; idx < cursor->top; idx++ )
		if( !idx ) {
			for( scan = cursor->rootlvl; scan--; )
				if( ch = (cursor->rootscan >> scan * 7) & 0x7F )
					if( off < max )
						buff[off++] = ch;
		} else if( off < max )
			if( ch = cursor->scan[idx] ) // skip slot zero
				buff[off++] = ch;

	//	pull rest of key from current entry in sorted array

	key = cursor->keys[cursor->idx].key;
	len = *key++;

	while( len-- && off < max )
		buff[off++] = *key++;

	buff[off] = 0;
	return off;
}

//	allocate hat node

void *hat_alloc (Hat *hat, uint type)
{
	uint amt, idx, round;
	HatSeg *seg;
	void *block;

	amt = HatSize[type];
	hat->counts[type]++;

	if( amt & (HAT_cache_line - 1) )
		amt |= (HAT_cache_line - 1), amt += 1;

	//	see if free block is already available

	if( (block = hat->reuse[type]) ) {
		hat->reuse[type] = *(void **)block;
		memset (block, 0, amt);
		return (void *)block;
	}

	if( hat->seg->next + amt > HAT_seg ) {
		if( (seg = malloc (HAT_seg)) ) {
			seg->next = sizeof(*seg);
			seg->seg = hat->seg;
			hat->seg = seg;
			if( round = (HatSlot)seg & (HAT_cache_line - 1) )
				seg->next += HAT_cache_line - round;
		} else {
			hat_abort("Out of virtual memory");
		}

		MaxMem += HAT_seg;
	}

	block = (void *)((uchar *)hat->seg + hat->seg->next);
	hat->seg->next += amt;
	memset (block, 0, amt);

	return block;
}

void *hat_data (Hat *hat, uint amt)
{
	HatSeg *seg;
	void *block;
	uint round;

	if( amt & (HAT_cache_line - 1))
		amt |= (HAT_cache_line - 1), amt += 1;

	if( hat->seg->next + amt > HAT_seg ) {
		if( (seg = malloc (HAT_seg)) ) {
			seg->next = sizeof(*seg);
			seg->seg = hat->seg;
			hat->seg = seg;
			if( round = (HatSlot)seg & (HAT_cache_line - 1) )
				seg->next += HAT_cache_line - round;
		} else {
			hat_abort("Out of virtual memory");
		}
	
		MaxMem += HAT_seg;
	}

	block = (void *)((uchar *)hat->seg + hat->seg->next);
	hat->seg->next += amt;
	memset (block, 0, amt);

	return block;
}

void hat_free (Hat *hat, void *block, int type)
{
	*((void **)(block)) = hat->reuse[type];
	hat->reuse[type] = (void **)block;
	hat->counts[type]--;
	return;
}
		
//	open hat object
//	call with number of radix levels to boot into root
//	and number of auxilliary user bytes to assign to each key

void *hat_open (int boot, int aux)
{
	uint amt, size = HAT_slot_size, round;
	HatSeg *seg;
	Hat *hat;
	int idx;

	for( idx = 0; idx < boot; idx++ )
		size *= 128;

	amt = sizeof(Hat) + size;

	if( amt & (HAT_cache_line - 1) )
		amt |= HAT_cache_line - 1, amt++;

	if( (seg = malloc(amt + HAT_seg)) ) {
		seg->next = sizeof(*seg);
		seg->seg = NULL;
		if( round = (HatSlot)seg & (HAT_cache_line - 1) )
			seg->next += HAT_cache_line - round;
	} else {
		hat_abort ("No virtual memory");
	}

	MaxMem += amt + HAT_seg;

	hat = (Hat *)((uchar *)seg + HAT_seg);

	memset(hat, 0, amt);
	hat->bootlvl = boot;
 	hat->aux = aux;
 	hat->seg = seg;

	if( !boot )
		*hat->root = (HatSlot)hat_alloc (hat, HAT_bucket) | HAT_bucket;

	return hat;
}

void hat_close (Hat *hat)
{
	HatSeg *seg, *nxt = hat->seg;

	while( (seg = nxt) )
		nxt = seg->seg, free (seg);
}

//	compute hash code for key

uint hat_code (uchar *buff, uint max)
{
	uint hash = max;

	while( max-- )
		hash += (hash << 5) + (hash >> 27) + *buff++;

	return hash;
}

void *hat_add_array (Hat *hat, HatSlot *parent, uchar *buff, uint amt, int pail);
void *hat_new_array (Hat *hat, HatSlot *parent, uchar *buff, uint amt);

//	add new key to existing HAT_pail node
//	return auxilliary area pointer, or
//	NULL if it doesn't fit PAIL array

void *hat_add_pail (Hat *hat, HatSlot *parent, uchar *buff, uint amt)
{
	HatPail *pail = (HatPail *)(*parent & HAT_mask);
	uint slot = hat_code (buff, amt) % HatPailMax;
	void *cell;

	if( !pail->array[slot] )
		return hat_new_array (hat, &pail->array[slot], buff, amt);

	//	does room exist in slot?

	if( cell = hat_add_array (hat, &pail->array[slot], buff, amt, 0) )
		return cell;

	return NULL;
}

//	create new HAT_pail node
//	from full HAT array node
//	by bursting it

void *hat_new_pail (Hat *hat, HatSlot *parent, uchar *buff, uint amt)
{
	HatBase *base = (HatBase *)(*parent & HAT_mask);
	ushort tst = 0, len, cnt = 0;
	HatPail *pail;
	uchar *cell;
	uint code;

	// strip array node keys into HAT_pail structure

	pail = hat_alloc (hat, HAT_pail);
	*parent = (HatSlot)pail | HAT_pail;

	//	burst array node into new PAIL node

	while( tst < base->nxt ) {
		len = base->keys[tst++];

		if( len & 0x80 )
			len &= 0x7f, len += base->keys[tst++] << 7;

		code = hat_code (base->keys + tst, len) % HatPailMax;

		if( pail->array[code] ) {
			cell = hat_add_array (hat, &pail->array[code], base->keys + tst, len, 0);
			if( hat->aux )
				memcpy(cell, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux, hat->aux);
		} else {
			cell = hat_new_array (hat, &pail->array[code], base->keys + tst, len);
			if(  hat->aux )
				memcpy (cell, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux, hat->aux);
		}

		tst += len;
		cnt++;
	}

	hat_free (hat, base, base->type);
	return hat_add_pail (hat, parent, buff, amt);
}

//	promote full array nodes to next larger size
//	if configured, overflow to HAT_pail node

void *hat_promote (Hat *hat, HatSlot *parent, uchar *buff, int amt, int pail)
{
	HatBase *base = (HatBase *)(*parent & HAT_mask);
	uchar *oldslots, *newslots;
	ushort tst, len, skip;
	uint type, oldtype;
	HatBase *newbase;

	if( amt > 0x7f )
		skip = 2;
	else
		skip = 1;

	oldtype = type = base->type;
	oldslots = (uchar *)base + HatSize[type];

	//	calculate new array node big enough to contain keys
	//	and associated slots

	if( !hat->aux || base->cnt < 255 )
		do if( (base->cnt + 1) * hat->aux + base->nxt + amt + skip + sizeof(HatBase) > HatSize[type] )
			   continue;
			else
				break;
		while( type++ < HatMax );
	else
		type = HatMax + 1;

	//  see if new key fits into largest array
	//	if not, promote to HAT_pail as configured

	if( type > HatMax )
		if( pail && HatPailMax )
			return hat_new_pail (hat, parent, buff, amt);
		else
			return NULL;

	// promote node to next larger size

	newbase = hat_alloc (hat, type);
	*parent = (HatSlot)newbase | HAT_array;
	newslots = (uchar *)newbase + HatSize[type];

	//	copy old node contents

	memcpy (newbase->keys, base->keys, base->nxt);	// copy keys in node

	if( hat->aux )
		memcpy (newslots - base->cnt * hat->aux, oldslots - base->cnt * hat->aux, base->cnt * hat->aux);	//	copy user slots

	//	append new node

	tst = base->nxt;
	newbase->keys[tst] = amt & 0x7f;

	if( amt & 0x80 )
		newbase->keys[tst] |- 0x80, newbase->keys[tst + 1] = amt >> 7;

	memcpy (newbase->keys + tst + skip, buff, amt);

	newbase->nxt = tst + amt + skip;
	newbase->cnt = base->cnt + 1;
	newbase->type = type;

	hat_free (hat, base, oldtype);
	return newslots - newbase->cnt * hat->aux;
}

//	make new hat array node
//	to contain new key
//	guaranteed to fit

void *hat_new_array (Hat *hat, HatSlot *parent, uchar *buff, uint amt)
{
	uint type = HAT_1;
	HatBase *base;
	ushort skip;

	if( amt > 0x7f )
		skip = 2;
	else
		skip = 1;

	while( hat->aux + amt + skip + sizeof(HatBase) > HatSize[type] )
		type++;

	//	new key doesn't fit into largest array

	if( type > HatMax )
		return NULL;

	base = hat_alloc (hat, type);
	*parent = (HatSlot)base | HAT_array;

	base->keys[0] = amt & 0x7f;

	if( amt > 0x7f )
		base->keys[0] |= 0x80, base->keys[1] = amt >> 7;

	memcpy (base->keys + skip, buff, amt);
	base->nxt = amt + skip;
	base->type = type;
	base->cnt = 1;
	return (uchar *)base + HatSize[type] - hat->aux;
}

//	add to existing hat array node

//	return slot address
//	  or NULL if it doesn't fit

void *hat_add_array (Hat *hat, HatSlot *parent, uchar *buff, uint amt, int pail)
{
	HatBase *base;
	ushort skip;
	uint type;

	if( amt > 0x7f )
		skip = 2;
	else
		skip = 1;

	base = (HatBase *)(*parent & HAT_mask);
	type = base->type;

	// add key to existing array

	if( !hat->aux || base->cnt < 255 )
		if( (base->cnt + 1 ) * hat->aux + base->nxt + amt + skip + sizeof(HatBase) <= HatSize[type] ) {
			memcpy (base->keys + base->nxt + skip, buff, amt);
			base->keys[base->nxt] = amt & 0x7f;
			if( amt > 0x7f )
				base->keys[base->nxt] |= 0x80, base->keys[base->nxt + 1] = amt >> 7;
			base->nxt += amt + skip;
			base->cnt++;
			return (uchar *)base + HatSize[type] - base->cnt * hat->aux;
		}

	return hat_promote (hat, parent, buff, amt, pail);
}

//	burst full array node into new bucket node

void hat_burst_array (Hat *hat, HatSlot *parent)
{
	ushort tst, len, type, cnt;
	HatBucket *bucket;
	HatBase *base;
	uchar *cell;
	uint code;

	base = (HatBase *)(*parent & HAT_mask);
	type = base->type;
	cnt = tst = 0;

	//	allocate new bucket node

	bucket = hat_alloc (hat, HAT_bucket);
	*parent = (HatSlot)bucket | HAT_bucket;

	//	burst array node into new bucket node

	while( tst < base->nxt ) {
		len = base->keys[tst++];
		if( len > 0x7f )
			len &= 0x7f, len += base->keys[tst++] << 7;

		code = hat_code (base->keys + tst, len) % HatBucketSlots;

		if( bucket->slots[code] ) {
			cell = hat_add_array (hat, &bucket->slots[code], base->keys + tst, len, 1);
			if( hat->aux )
				memcpy (cell, (uchar *)base + HatSize[type] - (cnt + 1) * hat->aux, hat->aux);
		} else {
			cell = hat_new_array (hat, &bucket->slots[code], base->keys + tst, len);
			if( hat->aux )
				memcpy (cell, (uchar *)base + HatSize[type] - (cnt + 1) * hat->aux, hat->aux);
		}

		bucket->count++;
		tst += len;
		cnt++;
	}

	hat_free (hat, base, type);
}

//	burst overflowing HAT_pail hash table into HAT_bucket hash table

void hat_burst_pail (Hat *hat, HatSlot *parent)
{
	HatPail *pail = (HatPail *)(*parent & HAT_mask);
	ushort tst, len, type, cnt, idx;
	HatBucket *bucket;
	HatBase *base;
	uchar *cell;
	uint code;

	//	allocate new bucket node

	bucket = hat_alloc (hat, HAT_bucket);
	*parent = (HatSlot)bucket | HAT_bucket;

	//	burst pail array into new bucket node

	for( idx = 0; idx < HatPailMax; idx++ ) {
		base = (HatBase *)(pail->array[idx] & HAT_mask);
		if( !base )
			continue;

		cnt = tst = 0;

		while( tst < base->nxt ) {
			len = base->keys[tst++];

			if( len & 0x80 )
				len &= 0x7f, len += base->keys[tst++];

			code = hat_code (base->keys + tst, len) % HatBucketSlots;

			if( bucket->slots[code] ) {
				if( (bucket->slots[code] & HAT_type) == HAT_array ) {
					cell = hat_add_array (hat, &bucket->slots[code], base->keys + tst, len, 1);
					if( hat->aux )
						memcpy (cell, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux, hat->aux);
				} else {
					cell = hat_add_pail (hat, &bucket->slots[code], base->keys + tst, len);
					if( hat->aux )
						memcpy (cell, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux, hat->aux);
				}
			} else {
				cell = hat_new_array (hat, &bucket->slots[code], base->keys + tst, len);
				if( hat->aux )
					memcpy (cell, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux, hat->aux);
			}

			bucket->count++;
			tst += len;
			cnt++;
		}

		hat_free (hat, base, base->type);
	}
	hat_free (hat, pail, HAT_pail);
}

//	add key to HAT_bucket node

//	return 1 on success
//	  or 0 if bucket overflows

int hat_add_bucket (Hat *hat, HatSlot *parent, uchar *buff, uint amt, uchar *value)
{
	HatBucket *bucket;
	uchar *cell;
	uint code;

	bucket = (HatBucket *)(*parent & HAT_mask);
	code = hat_code (buff, amt) % HatBucketSlots;

	if( bucket->count++ < HatBucketMax )
		if( !bucket->slots[code] ) {
			cell = hat_new_array (hat, &bucket->slots[code], buff, amt);
			if( hat->aux )
				memcpy (cell, value, hat->aux);
			return 1;
		} else if( (bucket->slots[code] & HAT_type) == HAT_array ) {
			if( cell = hat_add_array (hat, &bucket->slots[code], buff, amt, 1) ) {
				memcpy (cell, value, hat->aux);
				return 1;
			} else
				return 0;
		} else
			if( cell = hat_add_pail (hat, &bucket->slots[code], buff, amt) ) {
				memcpy (cell, value, hat->aux);
				return 1;
			} else
				return 0;

	return 0;
}

void hat_burst_bucket (Hat *hat, HatSlot *parent);

//	burst HAT_bucket node node into HAT_radix entry
//	moving key over one offset

void hat_add_radix (Hat *hat, HatSlot *radix, uchar *buff, uint max, uchar *value)
{
	void *cell;
	uchar ch;

	//  shorten key by 1 byte

	if( max )
		ch = buff[0];
	else
		ch = 0;

	//  if radix slot is empty, create new HAT_array node

	if( !radix[ch] ) {
		cell = hat_new_array (hat, &radix[ch], buff + 1, max ? max - 1 : 0);
		if( hat->aux )
			memcpy (cell, value, hat->aux);
		return;
	}

	//  otherwise, add to existing node

	do switch( radix[ch] & HAT_type ) {
		case HAT_bucket:
			if( hat_add_bucket (hat, &radix[ch], buff + 1, max - 1, value) )
				return;

			hat_burst_bucket (hat, &radix[ch]);
			continue;

		case HAT_radix:
			radix = (HatSlot *)(radix[ch] & HAT_mask);
			hat_add_radix (hat, radix, buff + 1, max - 1, value);
			return;

		case HAT_array:
			if( cell = hat_add_array (hat, &radix[ch], buff + 1, max - 1, 1) ) {
				if( hat->aux )
					memcpy (cell, value, hat->aux);
				return;
			}

			hat_burst_array (hat, &radix[ch]);
			continue;

		case HAT_pail:
			if( cell = hat_add_pail (hat, &radix[ch], buff + 1, max - 1) ) {
				if( hat->aux )
					memcpy (cell, value, hat->aux);
				return;
			}

			hat_burst_pail (hat, &radix[ch]);
			continue;
		} while( 1 );
}

//	decompose full bucket to radix node

void hat_burst_bucket (Hat *hat, HatSlot *parent)
{
	HatPail *pail, *chain;
	HatBucket *bucket;
	HatSlot *radix;
	HatBase *base;
	uint hash, idx;
	ushort tst, cnt;
	uchar len;

	bucket = (HatBucket *)(*parent & HAT_mask);

	if( bucket->count < HatBucketMax )
		Small++;

	//	allocate new hat_radix node

	radix = hat_alloc (hat, HAT_radix);
	*parent = (HatSlot)radix | HAT_radix;

	for( hash = 0; hash < HatBucketSlots; hash++ )
		if( bucket->slots[hash] )
			switch( bucket->slots[hash] & HAT_type ) {
			case HAT_array:
				base = (HatBase *)(bucket->slots[hash] & HAT_mask);
				cnt = tst = 0;

				while( tst < base->nxt ) {
					len = base->keys[tst++];
					if( len > 0x7f )
						len &= 0x7f, len += base->keys[tst++] << 7;
					hat_add_radix (hat, radix, base->keys + tst, len, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux);
					tst += len;
					cnt++;
				}

				hat_free (hat, base, base->type);
				continue;

			case HAT_pail:
				pail = (HatPail *)(bucket->slots[hash] & HAT_mask);

				for( idx = 0; idx < HatPailMax; idx++ ) {
					base = (HatBase *)(pail->array[idx] & HAT_mask);

					if( !base )
						continue;

					cnt = tst = 0;

					while( tst < base->nxt ) {
						len = base->keys[tst++];

						if( len > 0x7f )
							len &= 0x7f, len += base->keys[tst++] << 7;

						hat_add_radix (hat, radix, base->keys + tst, len, (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux);
						tst += len;
						cnt++;
					}

					hat_free (hat, base, base->type);
				}
				hat_free (hat, pail, HAT_pail);
			}

	hat_free (hat, bucket, HAT_bucket);
}

int keycmp (uchar *str1, uchar *str2, uint len)
{
	while( len & (HAT_slot_size - 1) )
		if( len--, str1[len] != str2[len] )
			return 1;

	while( len )
		if( *(HatSlot *)str1 != *(HatSlot *)str2 )
			return 1;
		else {
			str1 += HAT_slot_size;
			str2 += HAT_slot_size;
			len -= HAT_slot_size;
		}

	return 0;
}

//	hat_find: find string in hat array
//	returning a pointer to associated slot

void *hat_find (Hat *hat, uchar *buff, uint max)
{
	HatSlot next, *table;
	HatBucket *bucket;
	HatBase *base;
	HatPail *pail;
	ushort tst, cnt;
	uint triple = 0;
	uint code, len;
	uint off = 0;
	uchar ch;

	for( tst = 0; tst < hat->bootlvl; tst++ ) {
		triple *= 128;
		if( off < max )
			triple += buff[off++];
	}

	next = hat->root[triple];

	while( next )
		switch( next & HAT_type ) {
		case HAT_array:
			base = (HatBase *)(next & HAT_mask);
			cnt = tst = 0;
			Searches++;

			//  find slot == key

			while( tst < base->nxt ) {
				Probes++;
				len = base->keys[tst++];	// key length

				if( len > 0x7f )
					len += base->keys[tst++] << 7;

				if( len == max - off )
					if( !keycmp (base->keys + tst, buff + off, len) )
						if( hat->aux )
							return (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux;
						else
							return (void *)1;
				tst += len;
				cnt++;
			}

			return NULL;

		case HAT_pail:
			pail = (HatPail *)(next & HAT_mask);
			Pail++;

			code = hat_code (buff + off, max - off) % HatPailMax;

			if( next = pail->array[code] )
				continue;

			return NULL;

		case HAT_bucket:
			bucket = (HatBucket *)(next & HAT_mask);
			Bucket++;

			code = hat_code (buff + off, max - off) % HatBucketSlots;

			if( next = bucket->slots[code] )
				continue;

			return NULL;

		case HAT_radix:
			table = (HatSlot *)(next & HAT_mask);
			Radix++;

			if( off < max )
				ch = buff[off++];
			else
				ch = 0;

			next = table[ch];
			continue;
		}

	return NULL;
}

//	hat_cell: add string to hat array
//	returning address of associated slot

void *hat_cell (Hat *hat, uchar *buff, uint max)
{
	HatSlot *table, *next, *parent, node;
	HatBucket *bucket;
	HatBase *base;
	HatPail *pail;
	ushort tst, cnt;
	uint triple = 0;
	uint len, code;
	uint off = 0;
	void *cell;
	uchar ch;

	for( tst = 0; tst < hat->bootlvl; tst++ ) {
		triple *= 128;
		if( off < max )
			triple += buff[off++];
	}

	next = &hat->root[triple];
	parent = NULL;

loop:
	while( node = *next )
		switch( node & HAT_type ) {
		case HAT_array:
			base = (HatBase *)(node & HAT_mask);
			cnt = tst = 0;

			//  find slot == key

			while( tst < base->nxt ) {
				len = base->keys[tst++];	// key length

				if( len > 0x7f )
					len += base->keys[tst++] << 7;

				if( len == max - off )
					if( !keycmp (base->keys + tst, buff + off, max - off) )
						if( hat->aux )
							return (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux;
						else
							return (void *)1;

				tst += len;
				cnt++;
			}

			//  if parent node is a full bucket node,
			//  burst it and loop to reprocess insert

			if( parent ) {
				if( bucket->count++ < HatBucketMax )
					if( cell = hat_add_array (hat, next, buff + off, max - off, 1) )
						if( hat->aux )
							return cell;
						else
							return (void *)0;

				hat_burst_bucket (hat, parent);
				next = parent;
				parent = NULL;
				continue;
			}

			// add new key to existing array or create new pail array node

			if( cell = hat_add_array (hat, next, buff + off, max - off, 1) )
				if( hat->aux )
					return cell;
				else
					return (void *)0;

			//  burst full array node into HAT_bucket node
			//  and loop to reprocess the insert

			hat_burst_array (hat, next);
			continue;

		case HAT_pail:
			pail = (HatPail *)(node & HAT_mask);

			//  find slot == key

			cnt = tst = 0;
			code = hat_code (buff + off, max - off) % HatPailMax;

			if( base = (HatBase *)(pail->array[code] & HAT_mask) )
				while( tst < base->nxt ) {
					len = base->keys[tst++];	// key length

					if( len > 0x7f )
						len += base->keys[tst++] << 7;

					if( len == max - off )
						if( !keycmp (base->keys + tst, buff + off, max - off) )
							if( hat->aux )
								return (uchar *)base + HatSize[base->type] - (cnt + 1) * hat->aux;
							else
								return (void *)1;

					tst += len;
					cnt++;
				}

			//  if parent node is a full bucket node,
			//  burst it and loop to reprocess insert

			if( parent ) {
				if( bucket->count++ < HatBucketMax )
					if( cell = hat_add_pail (hat, next, buff + off, max - off) )
						if( hat->aux )
							return cell;
						else
							return (void *)0;

				hat_burst_bucket (hat, parent);
				next = parent;
				parent = NULL;
				continue;
			}

			if( cell = hat_add_pail (hat, next, buff + off, max - off) )
				if( hat->aux )
					return cell;
				else
					return (void *)0;

			//  burst full pail node into HAT_bucket node
			//  and loop to reprocess the insert

			hat_burst_pail (hat, next);
			continue;

		case HAT_bucket:
			bucket = (HatBucket *)(node & HAT_mask);
			code = hat_code (buff + off, max - off) % HatBucketSlots;

			parent = next;
			next = &bucket->slots[code];
			continue;

		case HAT_radix:
			table = (HatSlot *)(node & HAT_mask);

			if( off < max )
				ch = buff[off++];
			else
				ch = 0;

			next = &table[ch];
			continue;
		}

	// place new array node under HAT_bucket
	//	loop if bucket overflows

	if( parent )
		if( bucket->count++ < HatBucketMax ) {
			if( cell = hat_new_array (hat, next, buff + off, max - off) )
				if( hat->aux )
					return cell;
				else
					return (void *)0;

			hat_burst_bucket (hat, parent);
			next = parent;
			parent = NULL;
			goto loop;
		}

	// place new array node under HAT_radix

	cell = hat_new_array (hat, next, buff + off, max - off);

	if( hat->aux )
		return cell;

	return (void *)0;
}

#if 0
struct i_cbc {
	uint8_t str[256];
	uint32_t addr;
};

int main(void)
{
	Hat *hat;
	int i;
	int boot = 3;
	struct i_cbc *entry;
	struct i_cbc *find_entry;

	char *test_strs[5] = {
		"Hello World",
		"Fuck This World",
		"I've seen it all",
		"You've always been daydremer",
		"shit!!"
	};

	uint32_t test_addr[5] = {
		0x11111111,
		0x22222222,
		0x33333333,
		0x44444444,
		0x55555555
	};

	hat = hat_open(boot, sizeof(struct i_cbc));
	
	for (i = 0  ; i < 5 ; i++) {
		entry = hat_cell(hat, test_strs[i], strlen(test_strs[i]));
		strcpy(entry->str, test_strs[i]);
		entry->addr = test_addr[i];
	}

	find_entry = hat_find(hat, "shit!!", strlen("shit!!"));
	if (find_entry) {
		printf("%s : 0x%08x\n", find_entry->str, find_entry->addr);
	}
	
	hat_close(hat);
}
#endif
