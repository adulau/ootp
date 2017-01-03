#include "fileio.h"
#include "xerr.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * load file into memory.
 */
char *file_load(char *fname)
{
  struct stat sb;
  char *buf;
  int fd, ret, len;

  ret = -1; /* fail */
  buf = (char*)0L;
  fd = -1; /* invalid */

  /* open file */
  if ((fd = open(fname, O_RDONLY, 0)) < 0) {
    xerr_warn("open(%s)", fname);
    goto file_load_out;
  }

  /* load metadata */
  if (fstat(fd, &sb) < 0) {
    xerr_warn("stat(%s)", fname);
    goto file_load_out;
  }

  /* allocate storage for file contents + null */
  if (!(buf = malloc(sb.st_size+1))) {
    xerr_warn("malloc(%d)", (int)sb.st_size+1);
    goto file_load_out;
  } 

  /* read file contents */
  if ((len = read(fd, buf, sb.st_size)) < 0) {
    xerr_warn("read(%s)", fname);
    goto file_load_out;
  }
      
  /* null terminate */
  buf[sb.st_size] = 0;

  if (len != sb.st_size) {
    xerr_warnx("short read(%s)", fname);
    goto file_load_out;
  }

  ret = 0; /* success */

file_load_out:

  if (fd != -1)
    close(fd);

  if ((ret == -1) && buf) {
    free(buf);
    buf = (char*)0L;
  }

  return buf;

} /* file_load */
