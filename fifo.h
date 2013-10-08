#ifndef __BUF_H__
#define __BUF_H__
#include <sys/types.h>

#define FIFO_BLOCKLEN 4096

typedef struct
{
  /* private variable: only access by member function */
  char *bytes;
  ssize_t len;
  /* internal bytes block size by malloc */
  ssize_t size;
} fifo_t;

fifo_t *fifo_init (ssize_t len_init);
char *fifo_head (fifo_t * fifo);
ssize_t fifo_len (fifo_t * fifo);
void fifo_free (fifo_t * fifo);
int fifo_in (fifo_t * fifo, const char *data, ssize_t data_len);
void fifo_out (fifo_t * fifo, ssize_t pop_len);
char *fifo_extend (fifo_t * fifo, ssize_t ext_len);


#endif
