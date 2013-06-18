
#ifndef __HATTRIE_H__
#define __HATTRIE_H__

typedef unsigned char uchar;
typedef unsigned int uint;
#define PRIuint			"u"

typedef struct Hat Hat;
typedef struct HatCursor HatCursor;

void *hat_open(int boot, int aux);
void hat_close(Hat *hat);
void *hat_data(Hat *hat, uint amt);
void *hat_cell(Hat *hat, uchar *buff, uint max);
void *hat_find(Hat *hat, uchar *buff, uint max);

void *hat_cursor(Hat *hat);
uint hat_key(HatCursor *cursor, uchar *buff, uint max);
int hat_nxt(HatCursor *cursor);
int hat_prv(HatCursor *cursor);
void *hat_slot(HatCursor *cursor);
void *hat_start(HatCursor *cursor, uchar *buff, uint max);
int hat_last(HatCursor *cursor);

#endif
