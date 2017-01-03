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
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <curl/curl.h>
#include <ctype.h>
#include "xerr.h"
#include "otplib.h"

/* 
 * XXX man page
 */
static void usage(void);
static int write_pidfile(char *fname);

#define REQ_MODE_HTTP 0x1
#define REQ_MODE_SMTP 0x2

#define NXT_FIELD(V1,V2)\
  f = strsep(&c, "\n");\
  if (!f) {\
    xerr_warnx("parse rx_buf fail at %s", V1);\
    continue;\
  }\
  V2 = c;\

size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata);
size_t curl_read_cb(void *ptr, size_t size, size_t nmemb, void *userdata);

char *global_token;
char *global_svc;
char *global_hdr_subject;
char *global_hdr_from;

int main(int argc, char **argv)
{
  extern char *ootp_version;
  struct sockaddr_un rx_path;
  pid_t pid_child;
  CURL *curl;
  struct curl_slist *smtp_rcpt = NULL;
  char rx_buf[1024], *c, *f, *msg_svc, *msg_user, *msg_loc, *msg_token;
  char msg_buf[1024], post_buf[1024], *msg_ue, *loc_ue, *rx_pathname;
  char buf[1024], *pid_fname, *url_http, *url_smtp, *url, *hdr_from;
  char *hdr_subject;
  int rx_sock, len, verbose, opt_version, daemon_mode, buf_l, i;
  int req_mode, isdigits, isemail;

  struct option longopts[] = {
    { "bind-path",            1, (void*)0L,    'b'},
    { "disable-daemon-mode",  0, (void*)0L,    'D'},
    { "from-address",         1, (void*)0L,    'f'},
    { "help",                 0, (void*)0L,    'h'},
    { "help",                 0, (void*)0L,    '?'},
    { "subject",              1, (void*)0L,    's'},
    { "smtp-url",             1, (void*)0L,    'S'},
    { "pidfile",              1, (void*)0L,    'P'},
    { "http-url",             1, (void*)0L,    'H'},
    { "verbose",              0, (void*)0L,    'v'},
    { "version",              1, &opt_version,  1},
    { 0, 0, 0, 0},
  };

  req_mode = 0;
  daemon_mode = 1;
  opt_version = 0;
  smtp_rcpt = (struct curl_slist*)0L;
  pid_fname = "/var/run/otp-tokend.pid";
  url_http = (char*)0L;
  url_smtp = (char*)0L;
  url = (char*)0L;
  hdr_from = "hotp@eng.oar.net";
  hdr_subject = "HOTP Token";
  verbose = 0;
  xerr_setid(argv[0]);
  rx_pathname = OTP_SEND_TOKEN_PATHNAME;

  while ((i = getopt_long(argc, argv, "b:Df:h?H:P:s:S:v", longopts,
    (int*)0L)) != -1) {

    switch (i) {

      case 'b':
        rx_pathname = optarg;
        break;

      case 'D':
        daemon_mode = 0;
        break;

      case 'f':
        hdr_from = optarg;
        break;

      case 'h':
      case '?':
        usage();
        exit(0);
        break;

      case 'P':
        pid_fname = optarg;
        break;

      case 's':
        hdr_subject = optarg;
        break;

      case 'S':
        url_smtp = optarg;
        break;

      case 'H':
        url_http = optarg;
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

  global_hdr_subject = hdr_subject;
  global_hdr_from = hdr_from;

  if (!url_http || !url_smtp)
    xerr_errx(1, "HTTP and SMTP url required.");

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

  /* write out pidfile */
  if (write_pidfile(pid_fname) < 0)
    xerr_errx(1, "write_pidfile(%s): fatal", buf);

  if ((rx_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
    xerr_err(1, "socket()");

  /* fail silently */
  umask(077);
  unlink(rx_pathname);

  if (bind(rx_sock, (struct sockaddr*)&rx_path, sizeof(rx_path)) < 0)
    xerr_err(1, "bind(%s)", rx_pathname);

  /* reap children */
  if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    xerr_errx(1, "signal(SIGCHLD)");

  while (1) {

    if ((len = recv(rx_sock, &rx_buf, sizeof(rx_buf), 0)) < 0)
      xerr_err(1, "recv()");

    if ((pid_child = fork()) == -1)
      xerr_err(1, "fork()");

    /* parent? */
    if (pid_child)
      continue;

    /* child */
    if (verbose > 2)
      xerr_info("Child pid=%lu.", (unsigned long)getpid());

    if (len == 0)
      xerr_errx(1, "rx_buf empty.");

    if (rx_buf[len - 1] != 0)
      xerr_errx(1, "recv(): rx_buf not null terminated, skipping.");

    c = rx_buf;

    msg_svc = rx_buf;
    NXT_FIELD("msg_user", msg_user);
    NXT_FIELD("msg_loc", msg_loc);
    NXT_FIELD("msg_token", msg_token);

    for (c = msg_token; *c; ++c)
      if (*c == '\n')
        *c = 0;

    /* guess destination.  All digits == http, @ == smtp */
    isdigits = 1;
    isemail = 0;
    for (c = msg_loc; *c; ++c) {
      if (!isdigit(*c))
        isdigits = 0;
      if (*c == '@')
        isemail = 1;
    }
    if (isdigits) {
      req_mode = REQ_MODE_HTTP;
      url = url_http;
    } else if (isemail) {
      req_mode = REQ_MODE_SMTP;
      url = url_smtp;
    } else {
      xerr_errx(1, "Req mode not set for %s.", msg_loc);
    }

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK)
      xerr_errx(1, "curl_global_init(): failed.");

    if (!(curl = curl_easy_init()))
      xerr_errx(1, "curl_easy_init()");

    if (curl_easy_setopt(curl, CURLOPT_URL, url) != CURLE_OK)
      xerr_errx(1, "curl_easy_setopt(url): failed.");

    if (verbose > 1)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    if (req_mode == REQ_MODE_HTTP) {

      if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        &curl_write_cb) != CURLE_OK) 
        xerr_errx(1, "curl_easy_setopt(CURLOPT_WRITEFUNCTION): failed.");

      snprintf(msg_buf, sizeof(msg_buf), "%s: %s", msg_svc, msg_token);

      if (!(msg_ue = curl_escape(msg_buf, 0)))
        xerr_errx(1, "curl_escape(%s): failed.", msg_buf);

      if (!(loc_ue = curl_escape(msg_loc, 0))) {
        free(msg_ue);
        xerr_errx(1, "curl_escape(%s): failed.", msg_loc);
      }

      snprintf(post_buf, sizeof(post_buf), "to=%s&msg=%s", loc_ue, msg_ue);

      if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_buf) != CURLE_OK)
        xerr_errx(1, "curl_easy_setopt(CURLOPT_POSTFIELDS, %s): failed.",
          post_buf);

      if (curl_easy_perform(curl) != CURLE_OK)
        xerr_errx(1, "curl_easy_perform(): failed.");

      if (verbose > 1)
        xerr_info("msg_buf=%s", msg_buf);

      curl_easy_cleanup(curl);

      curl_global_cleanup();

    } else if (req_mode == REQ_MODE_SMTP) {

      if (curl_easy_setopt(curl, CURLOPT_MAIL_FROM, hdr_from) != CURLE_OK)
        xerr_errx(1, "curl_easy_setopt(CURLOPT_MAIL_FROM): failed.");

      if (!(smtp_rcpt = curl_slist_append(smtp_rcpt, msg_loc)))
        xerr_errx(1, "curl_slist_append(smtp_rcpt, msg_loc): failed.");

      if (curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, smtp_rcpt) != CURLE_OK)
        xerr_errx(1, "curl_easy_setopt(CURLOPT_MAIL_RCPT): failed.");

      /* needed by read_cb */
      global_token = msg_token;
      global_svc = msg_svc;

      if (curl_easy_setopt(curl, CURLOPT_READFUNCTION,
        &curl_read_cb) != CURLE_OK)
        xerr_errx(1, "curl_easy_setopt(CURLOPT_READFUNCTION): failed.");

      if (curl_easy_perform(curl) != CURLE_OK)
        xerr_errx(1, "curl_easy_perform(): failed.");

      curl_slist_free_all(smtp_rcpt);

    } else {

      xerr_errx(1, "req_mode");

    }
   
    /* exit child */
    if (verbose > 2)
      xerr_info("child exit");
    exit(0);

  } /* forever waiting messages */

} /* main */

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

size_t curl_read_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
  size_t t, r;
  static int cd;

  if (cd == 0) {
    t = size*nmemb;
    r = snprintf(ptr, t,
      "From: %s <HOTP>\r\nSubject: %s\r\n\r\nToken for %s: %s\r\n",
      global_hdr_from, global_hdr_subject, global_svc, global_token);
    ++cd;
    return r;
  } else {
    return 0;
  }

}

void usage(void)
{
  extern char *ootp_version;
         
  fprintf(stderr, "otp-tokend [-?Dhv] [-b bind-path] [-f from-address] [-s subject]\n");
  fprintf(stderr, "           -S smtp-url [-P pidfile] -H http-url\n");

  printf("%s\n", ootp_version);

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

