#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <curl/curl.h>
#include <ctype.h>
#include "xerr.h"
#include "otplib.h"

/* XXX usage
 * XXX man page
 */

static u_long scan_ip(char *s);
static void usage(void);
static int write_pidfile(char *fname);

#define NXT_FIELD(V1,V2)\
  f = strsep(&c, "\n");\
  if (!f) {\
    xerr_warnx("parse rx_buf fail at %s", V1);\
    continue;\
  }\
  V2 = c;\

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata);

int main(int argc, char **argv)
{
  extern char *ootp_version;
  struct sockaddr_un rx_path;
  CURL *curl;
  char rx_buf[1024], *c, *f, *msg_svc, *msg_user, *msg_loc, *msg_token;
  char msg_buf[1024], post_buf[1024], *msg_ue, *loc_ue, *rx_pathname;
  char buf[1024], *pid_fname, *url;
  int rx_sock, len, verbose, opt_version, daemon_mode, buf_l, i;

  struct option longopts[] = {
    { "bind-path",            1, (void*)0L,    'b'},
    { "disable-daemon-mode",  1, (void*)0L,    'D'},
    { "help",                 0, (void*)0L,    'h'},
    { "help",                 0, (void*)0L,    '?'},
    { "pidfile",              1, (void*)0L,    'P'},
    { "url",                  1, (void*)0L,    'u'},
    { "verbose",              0, (void*)0L,    'v'},
    { "version",              1, &opt_version,  1},
    { 0, 0, 0, 0},
  };

  daemon_mode = 1;
  opt_version = 0;
  pid_fname = (char*)0L;
  url = (char*)0L;
  verbose = 0;
  xerr_setid(argv[0]);
  rx_pathname = OTP_SEND_TOKEN_PATHNAME;

  while ((i = getopt_long(argc, argv, "b:Dh?P:u:v", longopts,
    (int*)0L)) != -1) {

    switch (i) {

      case 'b':
        rx_pathname = optarg;
        break;

      case 'D':
        daemon_mode = 0;
        break;

      case 'h':
      case '?':
        usage();
        exit(0);
        break;

      case 'P':
        pid_fname = optarg;
        break;

      case 'u':
        url = optarg;
        break;

      case 'v':
        ++verbose;
        break;

      case 0:
        if (opt_version) {
          printf("%s\n", ootp_version);
          exit(0);
        }

      default:
        xerr_errx(1, "getopt_long(): fatal.");

    } /* switch */

  } /* while getopt_long() */

  if (!url)
    xerr_errx(1, "url required.");

  if (daemon_mode) {

    xerr_setsyslog2(1); /* use syslog for output */
      
    /* run in the background */
    if (daemon(0, 0) < 0)
      xerr_err(1, "dameon()");
      
  } /* daemon_mode */

  buf_l = snprintf(buf, sizeof(buf), "tokend start:");
  if (verbose > 1) {
    for (i = 0; i < argc; ++i)
      buf_l += snprintf(buf+buf_l, sizeof(buf)-buf_l, " %s", argv[i]);
  }
  xerr_info(buf);

  bzero(&rx_path, sizeof (rx_path));
  rx_path.sun_family = AF_UNIX;
  if (strlen(rx_pathname) >= sizeof(rx_path.sun_path))
    xerr_errx(1, "rx_pathname too long.");
  strncpy(rx_path.sun_path, rx_pathname, sizeof(rx_path.sun_path));

  /* construct pid file name */
  if (!pid_fname) {
      
    if (strcmp(rx_pathname, OTP_SEND_TOKEN_PATHNAME)) {
        
      snprintf(buf, sizeof(buf), "/var/run/otp-tokend.pid.%s",
        rx_pathname);
          
    } else {
    
      snprintf(buf, sizeof(buf), "/var/run/otp-tokend.pid");
        
    }
 
    pid_fname = (char*)&buf;
        
  }
    
  /* write out pidfile */
  if (write_pidfile(pid_fname) < 0)
    xerr_errx(1, "write_pidfile(%s): fatal", buf);

  if (!(curl = curl_easy_init()))
    xerr_errx(1, "curl_easy_init()");

  if ((rx_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
    xerr_err(1, "socket()");

  /* fail silently */
  umask(077);
  unlink(rx_pathname);

  if (bind(rx_sock, (struct sockaddr*)&rx_path, sizeof(rx_path)) < 0)
    xerr_err(1, "bind(%s)", rx_pathname);

  if (verbose > 1)
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

  if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK)
    xerr_errx(1, "curl_easy_setopt(url): failed.");

  if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
    &curl_write_cb) != CURLE_OK) 
    xerr_errx(1, "curl_easy_setopt(CURLOPT_WRITEFUNCTION): failed.");

  while (1) {

    if ((len = recv(rx_sock, &rx_buf, sizeof(rx_buf), 0)) < 0)
      xerr_err(1, "recv()");

    if (len == 0) {
      xerr_warnx("rx_buf empty.");
      continue;
    }

    if (rx_buf[len - 1] != 0) {
      xerr_warnx("recv(): rx_buf not null terminated, skipping.");
      continue;
    }

    c = rx_buf;

    msg_svc = rx_buf;
    NXT_FIELD("msg_user", msg_user);
    NXT_FIELD("msg_loc", msg_loc);
    NXT_FIELD("msg_token", msg_token);

    for (c = msg_token; *c; ++c)
      if (*c == '\n')
        *c = 0;

    snprintf(msg_buf, sizeof(msg_buf), "%s: %s", msg_svc, msg_token);

    if (!(msg_ue = curl_escape(msg_buf, 0))) {
      xerr_warnx("curl_escape(msg_buf): failed.");
      continue;
    }

    if (!(loc_ue = curl_escape(msg_loc, 0))) {
      xerr_warnx("curl_escape(msg_loc): failed.");
      free(msg_ue);
      continue;
    }

    snprintf(post_buf, sizeof(post_buf), "to=%s&msg=%s", loc_ue, msg_ue);

    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf) != CURLE_OK)
      xerr_errx(1, "curl_easy_setopt(CURLOPT_POSTFIELDS, %s): failed.",
        post_buf);

    if (curl_easy_perform(curl) != CURLE_OK)
      xerr_warnx("1, curl_easy_perform(): failed.");

    if (verbose > 1)
      xerr_info("msg_buf=%s", msg_buf);

  }

}

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  char *c;
  c = malloc((size*nmemb)+1);
  bcopy(ptr, c, size*nmemb);
  c[size*nmemb] = 0;
  xerr_info(c);
  free(c);
  return size*nmemb;
}

void usage(void)
{
}

/*
 * function: write_pidfile()
 *
 * Store proces ID in ASII to fname.
 *
 * returns: < 0 : fail
 *            0 : success
 */
int write_pidfile(char *fname)
{
  int fd, buf_l;
  char buf[512];

  buf_l = snprintf(buf, sizeof(buf), "%lu\n", (unsigned long)getpid());

  if ((fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0644)) < 0 ) {
    xerr_warn("open(%s)", fname);
    return -1;
  }

  if (write(fd, buf, buf_l) < 0) {
    xerr_warn("write(%s)", fname);
    close (fd);
    return -1;
  }

  return (close(fd));

} /* write_pidfile */

/*
 * function: scan_ip
 *
 *  IP address in string S is converted to a u_long
 *  (borrowed from tcpdump)
 *
 *  left shift any partial dotted quads, ie 10 is 0x0a000000 not 0x0a
 *  so scan_ip_prefix() works for standard prefix notation, ie 10/8
 */
u_long scan_ip(char *s)
{
  struct hostent *he;
  struct in_addr *ina;
  u_long addr = 0;
  uint n;
  int dns, shift;
  char *t;

  /* if there is anything ascii in here, this may be a hostname */
  for (dns = 0, t = s; *t; ++t) {
    if (islower((int)*t) || isupper((int)*t)) {
      dns = 1;
      break;
    }
  }

  if (dns) {

    if (!(he = gethostbyname(s)))
      goto numeric;

    if (he->h_addrtype != AF_INET)
      goto numeric;

    if (he->h_length != sizeof (uint32_t))
      goto numeric;

    ina = (struct in_addr*)*he->h_addr_list;
    return (ntohl(ina->s_addr));

  } /* dns */

  shift = 0;

numeric:
  while (1) {

    /* n is the nibble */
    n = 0;

    /* nibble's are . bounded */
    while (*s && (*s != '.') && (*s != ' ') && (*s != '\t'))
      n = n * 10 + *s++ - '0';

    /* shift in the nibble */
    addr <<=8;
    addr |= n & 0xff;
    ++shift;

    /* return on end of string */
    if ((!*s) || (*s == ' ') || (*s == '\t'))
      goto ndone;

    /* skip the . */
    ++s;
  } /* forever */

ndone:

  for (; shift < 4; ++shift)
    addr <<=8;

  return addr;

} /* scan_ip */

