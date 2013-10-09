#ifndef __BUF_H__
#define __BUF_H__
#include <sys/types.h>

#define FIFO_BLOCKLEN 4096

typedef struct
{
  /* private variable: only access by member function */
  char *bytes;  /* data inside fifo */
  ssize_t len;  /* data len */

  /* internal bytes block size by malloc */
  ssize_t size; /* fifo memory block len */
} fifo_t;

fifo_t *fifo_init (ssize_t init_len);
void fifo_free (fifo_t * fifo);

/*fifo_head returns pointer to first bytes in fifo */
char *fifo_head (fifo_t * fifo);
ssize_t fifo_len (fifo_t * fifo);

/* push @data into fifo */
int fifo_in (fifo_t * fifo, const char *data, ssize_t data_len);

/* pop @pop_len bytes out of fifo, after read using fifi_head*/
void fifo_out (fifo_t * fifo, ssize_t pop_len);

/* empty fifo bytes, set fifo->len = 0 */
void fifo_flush (fifo_t * fifo);

#endif
