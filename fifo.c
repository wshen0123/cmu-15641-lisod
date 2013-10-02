#include <stdlib.h>
#include <string.h>
#include "fifo.h"

fifo_t *
fifo_init (ssize_t len_init)
{
  ssize_t __len_temp;

  if (len_init > 0)
    __len_temp = (len_init / FIFO_BLOCKLEN + 1) * FIFO_BLOCKLEN;
  else
    __len_temp = FIFO_BLOCKLEN;

  fifo_t *fifo = malloc (sizeof (fifo_t));
  fifo->bytes = malloc (__len_temp);
  fifo->__len = __len_temp;
  fifo->len = 0;
  return fifo;
}

char *
fifo_head (fifo_t * fifo)
{
  return fifo->bytes;
}


ssize_t
fifo_len (fifo_t * fifo)
{
  return fifo->len;
}


void
fifo_in (fifo_t * fifo, char *data, ssize_t data_len)
{
  char *bytes_temp;
  ssize_t __len_temp;

  if (data_len > 0)
    {
      if (fifo->len + data_len > fifo->__len)
	{
	  __len_temp =
	    ((fifo->len + data_len) / FIFO_BLOCKLEN + 1) * FIFO_BLOCKLEN;
	  bytes_temp = malloc (__len_temp);

	  memcpy (bytes_temp, fifo->bytes, fifo->len);
	  memcpy (bytes_temp + fifo->len, data, data_len);
	  free (fifo->bytes);

	  fifo->bytes = bytes_temp;
	  fifo->len += data_len;
	  fifo->__len = __len_temp;
	}
      else
	{
	  memcpy (fifo->bytes + fifo->len, data, data_len);
	  fifo->len += data_len;
	}
    }
}


void
fifo_out (fifo_t * fifo, ssize_t pop_len)
{
  char *bytes_temp;
  ssize_t __len_temp;
  if (pop_len >= fifo->len)
    {
      if (fifo->__len > FIFO_BLOCKLEN)
	{
	  free (fifo->bytes);
	  fifo->bytes = malloc (FIFO_BLOCKLEN);
	}
      fifo->len = 0;
    }
  else if (pop_len > 0)
    {
      __len_temp =
	((fifo->len - pop_len) / FIFO_BLOCKLEN + 1) * FIFO_BLOCKLEN;
      if (__len_temp < (fifo->__len / 2))
	{
	  bytes_temp = malloc (__len_temp);
	  memcpy (bytes_temp, fifo->bytes + pop_len, fifo->len - pop_len);
	  free (fifo->bytes);
	  fifo->bytes = bytes_temp;
	  fifo->__len = __len_temp;
	}
      else
	{
	  memcpy (fifo->bytes, fifo->bytes + pop_len, fifo->len - pop_len);
	  fifo->len = fifo->len - pop_len;
	}
    }
}


char *
fifo_extend (fifo_t * fifo, ssize_t ext_len)
{
  char *bytes_temp;
  ssize_t __len_temp;

  if (ext_len > 0)
    {
      if (fifo->__len - fifo->len < ext_len)
	{
	  __len_temp =
	    ((ext_len + fifo->len) / FIFO_BLOCKLEN + 1) * FIFO_BLOCKLEN;
	  bytes_temp = malloc (__len_temp);
	  memcpy (bytes_temp, fifo->bytes, fifo->len);
	  free (fifo->bytes);
	  fifo->bytes = bytes_temp;
	  bytes_temp += fifo->len;
	  fifo->len += ext_len;
	  fifo->__len = __len_temp;
	}
      else
	{
	  bytes_temp = fifo->bytes + fifo->len;
	  fifo->len += ext_len;
	}
      return bytes_temp;
    }
  return NULL;
}

void
fifo_free (fifo_t * fifo)
{
  if (!fifo)
    return;
  free (fifo->bytes);
  free (fifo);
}
