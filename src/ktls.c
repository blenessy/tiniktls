// SPDX-License-Identifier: MIT

#include "ktls.h"

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/tls.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>  // Linux only - TODO for BSDs
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_SERVER_CERT_FILE "certs/server-cert.pem"
#define DEFAULT_SERVER_KEY_FILE "certs/server-key.pem"
#define DEFAULT_TLS_PORT 443
#define DEFAULT_BACKLOG 1024

#define CHILDFD 3
#define MAX_CMD_LEN 7     // strlen("CONNECT");
#define MAX_SCHEME_LEN 3  // strlen("tcp");
#define MAX_HOST_LEN 255
#define MAX_PORT_LEN 5  // strlen("65535")
#define MAX_URL_LEN 2048
#define MAX_CMDLINE_LEN (MAX_CMD_LEN + 1 + MAX_URL_LEN + 1)

// number of listening sockets and pending connections
#define BATCH_SIZE 256
#define MAX_EVENTS 32

#define PRINT_FATAL(...)        \
  fprintf(stderr, __VA_ARGS__); \
  fputc('\n', stderr);
#define PRINT_WARNING(...)        \
  if (verbosity > 0) {            \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr);          \
  }
#define PRINT_INFO(...)           \
  if (verbosity > 1) {            \
    fprintf(stdout, __VA_ARGS__); \
    fputc('\n', stdout);          \
  }
#define PRINT_DEBUG(...)          \
  if (verbosity > 2) {            \
    fprintf(stdout, __VA_ARGS__); \
    fputc('\n', stdout);          \
  }
#define PRINT_TRACE(...)          \
  if (verbosity > 3) {            \
    fprintf(stdout, __VA_ARGS__); \
    fputc('\n', stdout);          \
  }

typedef enum {
  STATE_NONE = 0x00,
  STATE_CHILDFD,
  STATE_TCP_CONNECTING,
  STATE_TLS_CONNECTING,
  STATE_TCP_ACCEPTING,
  STATE_TLS_ACCEPTING,
  STATE_TLS_SERVER_HANDSHAKING,    // need to SSL_accept until handshake is
                                   // completed
  STATE_TLS_CLIENT_HANDSHAKING,    // wait for SSL_connect until handshake is
                                   // completed
  STATE_KTLS_CLIENT_RECV_TICKET1,  // client receives
                                   // SSL3_RT_HANDSHAKE/SSL3_MT_NEWSESSION_TICKET
                                   // 1
  STATE_KTLS_CLIENT_RECV_TICKET2,  // client receives
                                   // SSL3_RT_HANDSHAKE/SSL3_MT_NEWSESSION_TICKET
                                   // 2
} ktls_state_t;

typedef enum {
  CMD_NONE = 0x00,
  CMD_CONNECT,
  CMD_ACCEPT,
  CMD_CLOSE,
} ktls_cmd_t;

typedef struct {
  SSL* ssl;
  ktls_state_t state;
  char cmdline[MAX_CMDLINE_LEN + 1];
} ktls_sockfd_t;

// https://delthas.fr/blog/2023/kernel-tls/
static const char* ktls12_cipher_list =
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:";

static const char* ktls13_cipher_suites =
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256";

static int childfd = -1;
static time_t poll_period_millis = 1000;
static int verbosity = 0;
static SSL_CTX* server_ctx = NULL;
static SSL_CTX* client_ctx = NULL;

// epoll stuff
static int epollfd = -1;

// sockfd stuff
static int last_sockfd = -1;
static ktls_sockfd_t* sockfds[BATCH_SIZE + 4] = {
    NULL};  // 4: stdin, stdout, stderr, childfd
static int default_sockfd_flags = 0;

// custom error messages
static char errmsg[121] = {'\0'};

static int setblocking(int sockfd, int blocking) {
  int flags = blocking ? default_sockfd_flags & ~O_NONBLOCK
                       : default_sockfd_flags | O_NONBLOCK;
  return fcntl(sockfd, F_SETFL, flags);
}

static int sockfd_socket() {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd == -1) {
    return -1;
  }
  int on = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on))) {
    close(fd);
  }
  return fd;
}

static void sockfd_close(int* fdp) {
  if (fdp == NULL || *fdp < 0) {  // idempotency check
    return;
  }
  int fd = *fdp;
  *fdp = -1;

  // shutdown SSL
  if (sockfds[fd] != NULL) {
    if (sockfds[fd]->ssl != NULL) {
      SSL_shutdown(sockfds[fd]->ssl);
      SSL_free(sockfds[fd]->ssl);
    }
    free(sockfds[fd]);
    sockfds[fd] = NULL;
  }

  // stop polling fd
  if (epollfd != -1 && epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL)) {
    PRINT_DEBUG("epoll_ctl(EPOLL_CTL_DEL, %d) failed: %s", fd, strerror(errno));
  }

  // close the socket
  if (close(fd)) {
    PRINT_WARNING("close(%d) failed", fd);
  }

  while (last_sockfd >= 0 && sockfds[last_sockfd] == NULL) {
    last_sockfd -= 1;  // decrease last_sockfd
  }
}

int find_accept_cmd(const char* url) {
  char* key = "ACCEPT ";
  size_t len = strlen(key);
  for (int i = 0; i <= last_sockfd; i++) {
    if (sockfds[i] == NULL || memcmp(sockfds[i]->cmdline, key, len) != 0) {
      continue;
    }
    if (strcmp(&(sockfds[i]->cmdline)[len], url) == 0) {
      return i;
    }
  }
  sprintf(errmsg, "listening socket already closed");
  return -1;
}

static void global_cleanup() {
  if (client_ctx != NULL) {
    SSL_CTX_free(client_ctx);
    client_ctx = NULL;
  }
  if (server_ctx != NULL) {
    SSL_CTX_free(server_ctx);
    server_ctx = NULL;
  }
  for (int i = 0; i <= last_sockfd; i++) {
    if (sockfds[i] != NULL) {
      int tempfd = i;
      sockfd_close(&tempfd);
    }
  }
  if (epollfd != -1) {
    close(epollfd);
    epollfd = -1;
  }
  verbosity = 0;
}

static int recv_child(int fd, char* buf, size_t bufsize) {
  memset(buf, 0, bufsize);
  int len = recv(fd, buf, bufsize, MSG_PEEK);
  if (len > 0) {
    // find the last NL
    for (int i = 0; i < len; i++) {
      if (buf[i] == '\n') {
        // read only complete lines
        return recv(fd, buf, i + 1, 0);
      }
    }
    // skip past garbage
    PRINT_WARNING("skipping %d bytes of garbage from child", len);
    recv(fd, buf, bufsize, 0);
    return 0;
  }
  return len;
}

static int parse_url(char* url, int* tlsp, char** hostp, int* portp) {
  // parse the scheme
  char* token = strtok(url, ":");
  if (token == NULL) {
    sprintf(errmsg, "invalid URL: missing ':'");
    return -1;
  }
  if (strcmp(token, "tcp") == 0) {
    *tlsp = 0;
  } else if (strcmp(token, "tls") == 0) {
    *tlsp = 1;
  } else {
    sprintf(errmsg, "invalid URL: unsupported schema");
    return -1;
  }

  // parse host
  token = strtok(NULL, ":");
  assert(token != NULL);
  token += 2;  // skip the "//"
  size_t len = strlen(token);
  if (len > MAX_HOST_LEN) {
    sprintf(errmsg, "invalid URL: hostname length > %d", MAX_HOST_LEN);
    return -1;
  }
  // memcpy(cmd_ptr->host, token, len);
  // sockfd_ptr->host[len] = '\0';
  *hostp = token;

  // parse the port number
  token = strtok(NULL, "?/");
  if (token != NULL) {
    long port = strtol(token, NULL, 10);
    if (port < 0 || port > USHRT_MAX) {
      sprintf(errmsg, "invalid URL: invalid port: %ld", port);
      return -1;
    }
    *portp = (int)port;
  } else if (*tlsp) {
    *portp = DEFAULT_TLS_PORT;
  } else if (token == NULL) {
    sprintf(errmsg, "invalid URL: no TCP port specified");
    return -1;
  }
  return 0;
}

static int find_query_arg(char* url, char* key, char* value, int size) {
  assert(url != NULL && key != NULL && value != NULL);
  char* p = strchr(url, '?');  // skip to query string
  int keylen = strlen(key);
  while (p != NULL) {
    p += 1;
    if (strncmp(p, key, keylen) == 0) {
      // calculate the arg length
      p += keylen;
      char* q = strchr(p, '&');
      int len = q == NULL ? strlen(p) : (size_t)(q - p);
      if (len >= size) {
        break;
      }
      memcpy(value, p, len);
      value[len] = '\0';
      return 0;
    }
    // find start of next arg
    p = strchr(p, '&');
  }
  return -1;
}

static int sockfd_open(int fd, uint32_t events, const ktls_sockfd_t* sockfd) {
  // only allocate what we will actually use.
  assert(fd != -1);
  assert(sockfds[fd] == NULL);
  size_t sockfd_size =
      sizeof(ktls_sockfd_t) - MAX_CMDLINE_LEN + strlen(sockfd->cmdline);
  ktls_sockfd_t* sockfd2 = (ktls_sockfd_t*)malloc(sockfd_size);
  if (sockfd2 == NULL) {
    goto error_cleanup;
  }
  memcpy(sockfd2, sockfd, sockfd_size);
  struct epoll_event event = {
      .events = events,
      .data.fd = fd,
  };
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event)) {
    goto error_cleanup;
  }
  sockfds[fd] = sockfd2;
  if (last_sockfd < fd) {
    last_sockfd = fd;
  }

  return 0;

error_cleanup:
  if (sockfd2 != NULL) {
    free(sockfd2);
  }
  return -1;
}

static int sockfd_listen(int fd, const char* host, int port, int backlog) {
  struct sockaddr_in addr = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr.s_addr = inet_addr(host),
  };

  int on = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
    PRINT_WARNING("setsockopt(%d, SOL_SOCKET, SO_REUSEADDR) failed", fd);
    return -1;
  }

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr))) {
    PRINT_FATAL("bind(%d) failed", fd);
    return -1;
  }

  if (listen(fd, backlog)) {
    PRINT_FATAL("listen(%d) failed", fd);
    return -1;
  }
  return 0;
}

int sockfd_connect(int fd, const char* host, int port) {
  struct addrinfo* ai_list = NULL;
  int ret = -1;
  if ((ret = getaddrinfo(host, NULL, NULL, &ai_list))) {
    goto error_cleanup;
  }

  struct sockaddr* addr = NULL;
  for (struct addrinfo* ai = ai_list; ai != NULL; ai = ai->ai_next) {
    if (ai->ai_family == AF_INET && ai->ai_socktype == SOCK_STREAM) {
      addr = ai->ai_addr;
      ((struct sockaddr_in*)addr)->sin_port = htons(port);
      break;  // no point if looking further
    } else if (ai->ai_family == AF_INET6 && ai->ai_socktype == SOCK_STREAM) {
      addr = ai->ai_addr;
      ((struct sockaddr_in6*)addr)->sin6_port = htons(port);
    }
  }

  if (addr == NULL) {
    ret = -1;
    sprintf(errmsg, "failed to resolve hostname");
    goto error_cleanup;
  }

  if ((ret = connect(fd, addr, sizeof(*addr))) && errno != EINPROGRESS) {
    goto error_cleanup;
  }
  ret = 0;

error_cleanup:
  if (ai_list != NULL) {
    freeaddrinfo(ai_list);
  }
  return ret;
}

static int ktls_recv_ticket(int fd) {
  // https://datatracker.ietf.org/doc/html/rfc8446#section-4.6.1
  // https://www.ibm.com/docs/en/sdk-java-technology/8?topic=handshake-session-resumption-pre-shared-key
  // For TLS 1.3 the KTLS send 2 x NewSessionTickets post handshake.
  // If we don't consume those before handing over the socket to the child,
  // KTLS will fail with IOE.

  // Expected data length is 0x000035 - adding some slack
  // https://www.ibm.com/docs/en/ztpf/2023?topic=sessions-ssl-record-format
  char buf[16384];
  char cmsg[CMSG_SPACE(sizeof(unsigned char))];
  struct msghdr msg = {0};
  msg.msg_control = cmsg;
  msg.msg_controllen = sizeof(cmsg);

  struct iovec msg_iov;
  msg_iov.iov_base = buf;
  msg_iov.iov_len = sizeof(buf);
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  // peek first so we don't consume the application data.
  int ret = recvmsg(fd, &msg, MSG_PEEK);
  if (ret == -1) {
    return -1;
  }

  ret = -2;
  struct cmsghdr* hdr = CMSG_FIRSTHDR(&msg);
  if (hdr->cmsg_level != SOL_TLS || hdr->cmsg_type != TLS_GET_RECORD_TYPE) {
    sprintf(errmsg, "unexpected CMSG level (%d) or type (%d)", hdr->cmsg_level,
            hdr->cmsg_type);
    goto error_cleanup;
  }

  int record_type = *((unsigned char*)CMSG_DATA(hdr));
  if (record_type != SSL3_RT_HANDSHAKE || buf[0] != SSL3_MT_NEWSESSION_TICKET) {
    sprintf(errmsg, "unexpected TLS record type: %d", record_type);
    goto error_cleanup;
  }

  ret = 0;

error_cleanup:
  // consume the ticket
  recvmsg(fd, &msg, 0);
  return ret;
}

static int send_child(const char* cmdline, int* fdp, const char* err) {
  // http://liujunming.top/2024/07/14/File-Descriptor-Transfer-over-Unix-Domain-Sockets/
  // create the message
  assert(childfd != -1);
  assert(cmdline != NULL);
  assert(fdp == NULL || *fdp != -1);

  char* prefix = err != NULL ? "ERR" : "OK";
  size_t errlen = err != NULL ? strlen(err) + 1 : 0;
  size_t buflen = strlen(prefix) + 1 + strlen(cmdline) + 1 + errlen;
  char buf[buflen + 1];  // add space for null-terminator
  char* ptr = stpcpy(buf, prefix);
  *ptr = ' ';
  ptr = stpcpy(&ptr[1], cmdline);
  if (err != NULL) {
    *ptr = ' ';
    ptr = stpcpy(&ptr[1], err);
  }
  *ptr = '\n';
  struct iovec iov = {
      .iov_base = buf,
      .iov_len = buflen,
  };

  // the expected msghdr by sendmsg
  struct msghdr msgh = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  if (fdp != NULL) {
    // the optional file descriptor that we want to send
    // Allocate a char array of suitable size to hold the ancillary data.
    // However, since this buffer is in reality a 'struct cmsghdr', use a
    // union to ensure that it is aligned as required for that structure.
    union {
      char buf[CMSG_SPACE(sizeof(int))];
      struct cmsghdr align;
    } cmsg;
    memset(cmsg.buf, 0, sizeof(cmsg.buf));

    msgh.msg_control = cmsg.buf;
    msgh.msg_controllen = sizeof(cmsg.buf);

    struct cmsghdr* cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsgp), fdp, sizeof(*fdp));

    // most pass expect a blocking socket
    if (setblocking(*fdp, 1)) {
      return -1;
    }
  }
  if (sendmsg(childfd, &msgh, 0) == -1) {
    PRINT_FATAL("sendmsg(%d) failed", childfd);
    return -1;
  }
  sockfd_close(fdp);  // close the socket eagerly if we managed to send it

  return 0;
}

static int handle_tls_client_handshaking(int fd) {
  SSL* ssl = sockfds[fd]->ssl;
  assert(ssl != NULL);

  int ret = SSL_connect(ssl);
  int ssl_err = SSL_get_error(ssl, ret);
  if (ret <= 0 &&
      (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)) {
    return 0;  // handshake ongoing => continue polling
  } else if (ret <= 0) {
    sprintf(errmsg, "SSL_connect failed: %d", ssl_err);
    return -1;
  }

  // close the SSL session without closing the underlying file descriptor
  assert(SSL_is_init_finished(ssl));
  int version = SSL_version(ssl);

  // done with SSL - lets free it eagerly
  SSL_set_fd(ssl, -1);
  SSL_free(ssl);
  sockfds[fd]->ssl = NULL;

  // TLS1.3 has post-handshake messages
  if (version == TLS1_3_VERSION) {
    PRINT_DEBUG("fd %d -> STATE_KTLS_CLIENT_RECV_TICKET1", fd);
    sockfds[fd]->state = STATE_KTLS_CLIENT_RECV_TICKET1;
    return 0;
  }

  PRINT_DEBUG("TLS connection established on fd: %d", fd)
  return send_child(sockfds[fd]->cmdline, &fd, NULL);
}

static void get_hostname_from_cmd(char* cmd, char* hostname) {
  assert(hostname != NULL);
  char* start = strstr(cmd, "://");
  assert(start != NULL);
  start += strlen("://");
  char* end = start;
  while (*end != ':' && *end != '/' && *end != '\0') {
    end++;
  }
  int len = end - start;
  memcpy(hostname, start, len);
  hostname[len] = '\0';
}

static int limit_cipher(SSL* ssl, char* cmd) {
  char arg[PATH_MAX + 1];
  if (find_query_arg(cmd, "tls=", arg, sizeof(arg)) == 0) {
    if (strcmp(arg, "1.2") == 0) {
      if (!SSL_set_max_proto_version(ssl, TLS1_2_VERSION)) {
        sprintf(errmsg, "SSL_set_max_proto_version failed");
        return -1;
      }
      if (find_query_arg(cmd, "ciphers=", arg, sizeof(arg)) == 0) {
        if (!SSL_set_cipher_list(ssl, arg)) {
          sprintf(errmsg, "SSL_set_cipher_list failed");
          return -1;
        }
      }
    } else if (strcmp(arg, "1.3") == 0) {
      if (!SSL_set_min_proto_version(ssl, TLS1_3_VERSION)) {
        sprintf(errmsg, "SSL_set_min_proto_version failed");
        return -1;
      }
      if (find_query_arg(cmd, "ciphers=", arg, sizeof(arg)) == 0) {
        if (!SSL_set_ciphersuites(ssl, arg)) {
          sprintf(errmsg, "SSL_set_ciphersuites failed");
          return -1;
        }
      }
    }
  }
  return 0;
}

static int handle_tls_connecting(int fd) {
  SSL* ssl = SSL_new(client_ctx);
  if (ssl == NULL) {
    return -1;
  }

  /* Set hostname for SNI */
  char snihost[MAX_HOST_LEN + 1];
  get_hostname_from_cmd(sockfds[fd]->cmdline, snihost);
  int ret = -1;
  if (!SSL_set_tlsext_host_name(ssl, snihost)) {
    sprintf(errmsg, "SSL_set_tlsext_host_name failed");
    goto error_cleanup;
  } else if (!SSL_set1_host(ssl, snihost)) {
    sprintf(errmsg, "SSL_set1_host failed");
    goto error_cleanup;
  }

  if ((ret = limit_cipher(ssl, sockfds[fd]->cmdline))) {
    goto error_cleanup;
  }

  int verify_mode = SSL_VERIFY_PEER;
  char arg[PATH_MAX + 1];
  if (find_query_arg(sockfds[fd]->cmdline, "verify=", arg, sizeof(arg)) == 0 &&
      strcmp(arg, "0") == 0) {
    verify_mode = SSL_VERIFY_NONE;
  }
  SSL_set_verify(ssl, verify_mode, NULL);

  if (!SSL_set_fd(ssl, fd)) {
    sprintf(errmsg, "SSL_set_fd failed");
    goto error_cleanup;
  }

  PRINT_DEBUG("fd %d -> STATE_TLS_CLIENT_HANDSHAKING", fd);
  sockfds[fd]->ssl = ssl;
  sockfds[fd]->state = STATE_TLS_CLIENT_HANDSHAKING;

  if ((ret = handle_tls_client_handshaking(fd)) == 0) {
    return 0;
  }

error_cleanup:
  if (ssl != NULL) {
    SSL_free(ssl);
  }
  return ret;
}

static int handle_childfd_event() {
  ktls_sockfd_t sockfd = {.state = STATE_NONE};
  int fd = -1;
  char cmdline[MAX_CMDLINE_LEN + 1];

  assert(childfd != -1);
  int ret = recv_child(childfd, cmdline, MAX_CMDLINE_LEN);
  if (ret < 0) {
    PRINT_FATAL("recv_child failed");
    goto error_cleanup;
  } else if (ret == 0) {
    PRINT_DEBUG("childfd closed");
    sockfd_close(&childfd);
    goto error_cleanup;
  }

  cmdline[ret - 1] = '\0';  // properly terminate line for strtok
  PRINT_INFO("command: \"%s\"", cmdline);
  memcpy(sockfd.cmdline, cmdline, ret);  // copy the null terminator too

  // parse the command
  ret = -1;
  char* token = strtok(cmdline, " ");
  if (token == NULL) {
    sprintf(errmsg, "invalid command line recieved");
    goto error_cleanup;
  }
  ktls_cmd_t cmd = CMD_CLOSE;
  if (strcmp(token, "CONNECT") == 0) {
    cmd = CMD_CONNECT;
  } else if (strcmp(token, "ACCEPT") == 0) {
    cmd = CMD_ACCEPT;
  } else if (strcmp(token, "CLOSE") != 0) {
    sprintf(errmsg, "invalid command recieved");
    goto error_cleanup;
  }

  // parse the url
  token = strtok(NULL, " ");
  if (token == NULL) {
    goto error_cleanup;
  }

  int backlog = DEFAULT_BACKLOG;
  if (cmd == CMD_CLOSE) {
    if ((fd = find_accept_cmd(token)) != -1) {
      sockfd_close(&fd);
      ret = send_child(sockfd.cmdline, NULL, NULL);
    }
    goto error_cleanup;
  } else if (cmd == CMD_ACCEPT) {
    char arg[11];  // strlen("2147483647") + 1
    if (find_query_arg(token, "backlog=", arg, sizeof(arg)) == 0) {
      backlog = strtol(arg, NULL, 10);
      if (backlog < 1) {
        sprintf(errmsg, "invalid backlog: %i", backlog);
        ret = -1;
        goto error_cleanup;
      }
    }
  }

  int tls = 0;
  char* host = NULL;
  int port = 0;
  if ((ret = parse_url(token, &tls, &host, &port)) != 0) {
    sprintf(errmsg, "invalid URL specified");
    goto error_cleanup;
  }

  if ((ret = fd = sockfd_socket()) < 0) {
    sprintf(errmsg, "could not create socket");
    goto error_cleanup;
  }
  if ((ret = sockfd_open(fd, EPOLLIN | EPOLLOUT | EPOLLET, &sockfd))) {
    goto error_cleanup;
  }

  assert(sockfds[fd] != NULL);
  assert(cmd != CMD_CLOSE);
  if (cmd == CMD_CONNECT) {
    if (tls) {
      sockfds[fd]->state = STATE_TLS_CONNECTING;
      PRINT_DEBUG("fd %d -> STATE_TLS_CONNECTING", fd);
    } else {
      sockfds[fd]->state = STATE_TCP_CONNECTING;
      PRINT_DEBUG("fd %d -> STATE_TCP_CONNECTING", fd);
    }
  } else {
    if (tls) {
      sockfds[fd]->state = STATE_TLS_ACCEPTING;
      PRINT_DEBUG("fd %d -> STATE_TLS_ACCEPTING", fd);
    } else {
      sockfds[fd]->state = STATE_TCP_ACCEPTING;
      PRINT_DEBUG("fd %d -> STATE_TCP_ACCEPTING", fd);
    }
  }

  if (cmd == CMD_CONNECT) {
    if ((ret = sockfd_connect(fd, host, port))) {
      goto error_cleanup;
    }
  } else {
    if ((ret = sockfd_listen(fd, host, port, backlog))) {
      goto error_cleanup;
    }
  }

  // register the socket in sockfd table
  return 0;

error_cleanup:
  if (fd != -1) {
    close(fd);
  }
  return ret;
}

static int handle_tls_server_handshaking(int fd) {
  SSL* ssl = sockfds[fd]->ssl;
  assert(ssl != NULL);
  int ret = SSL_accept(ssl);
  int ssl_err = SSL_get_error(ssl, ret);
  if (ret <= 0 &&
      (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)) {
    errno = EAGAIN;
    return -1;  // handshake ongoing => continue polling
  } else if (ret <= 0) {
    sprintf(errmsg, "SSL_accept failed: %d", ssl_err);
    return -1;
  }

  // close the SSL session without closing the underlying file descriptor
  assert(SSL_is_init_finished(ssl));
  SSL_set_fd(ssl, -1);
  SSL_free(ssl);
  sockfds[fd]->ssl = NULL;

  return 0;
}

static int handle_tls_accepting(int fd) {
  assert(sockfds[fd]->cmdline != NULL);
  int connfd, ret;
  SSL* ssl = NULL;
  ret = connfd = accept(fd, NULL, 0);
  if (ret == -1) {
    goto error_cleanup;
  }
  if ((ret = setblocking(connfd, 0))) {
    goto error_cleanup;
  }

  if ((ssl = SSL_new(server_ctx)) == NULL) {
    errno = ENOMEM;
    ret = -1;
    goto error_cleanup;
  }

  if ((ret = limit_cipher(ssl, sockfds[fd]->cmdline))) {
    goto error_cleanup;
  }

  ret = -1;
  char arg[PATH_MAX + 1];
  if (find_query_arg(sockfds[fd]->cmdline, "cert=", arg, sizeof(arg)) == 0) {
    if (!SSL_use_certificate_chain_file(ssl, arg)) {
      sprintf(errmsg, "SSL_use_certificate_chain_file failed");
      goto error_cleanup;
    }
  }
  if (find_query_arg(sockfds[fd]->cmdline, "key=", arg, sizeof(arg)) == 0) {
    if (!SSL_use_PrivateKey_file(ssl, arg, SSL_FILETYPE_PEM)) {
      sprintf(errmsg, "SSL_use_PrivateKey_file failed");
      goto error_cleanup;
    }
    if (!SSL_check_private_key(ssl)) {
      sprintf(errmsg, "SSL_check_private_key failed");
      goto error_cleanup;
    }
  }

  if (!SSL_set_fd(ssl, connfd)) {
    sprintf(errmsg, "SSL_set_fd failed");
    goto error_cleanup;
  }

  // create a new sockfd from the listening socket
  if ((ret = sockfd_open(connfd, EPOLLIN | EPOLLET, sockfds[fd]))) {
    goto error_cleanup;
  }
  sockfds[connfd]->ssl = ssl;
  ssl = NULL;  // prevent double free
  sockfds[connfd]->state = STATE_TLS_SERVER_HANDSHAKING;

  PRINT_DEBUG("fd %d -> STATE_TLS_SERVER_HANDSHAKING", connfd);
  if ((ret = handle_tls_server_handshaking(connfd)) != -1 || errno != EAGAIN) {
    goto error_cleanup;
  }
  return 0;

error_cleanup:
  if (connfd != -1) {
    close(connfd);
  }
  if (ssl != NULL) {
    SSL_free(ssl);
  }
  return ret;
}

int ktls_serve() {
  assert(epollfd != -1);
  struct epoll_event epoll_events[MAX_EVENTS];  // make space for childfd
  int ret, nfds;

  ret = nfds =
      epoll_wait(epollfd, epoll_events, MAX_EVENTS, poll_period_millis);
  if (ret == -1) {
    PRINT_FATAL("epoll_wait failed");
    goto error_cleanup;
  }

  for (int i = 0; i < nfds; i++) {
    int events = epoll_events[i].events;
    int fd = epoll_events[i].data.fd;
    assert(sockfds[fd] != NULL);
    assert(sockfds[fd]->state != STATE_NONE);
    assert(sockfds[fd]->cmdline != NULL);
    errno = 0;
    errmsg[0] = '\0';
    PRINT_DEBUG("epoll events: 0x%04x (fd=%d)", events, fd)
    switch (sockfds[fd]->state) {
      case STATE_CHILDFD: {
        if ((ret = handle_childfd_event())) {
          PRINT_FATAL("handle_childfd_event failed");
        }
        break;
      }
      case STATE_TCP_ACCEPTING: {
        int connfd = ret = accept(fd, NULL, 0);
        if (connfd >= 0) {
          PRINT_DEBUG("TCP connection accepted on fd: %d", fd)
          if ((ret = send_child(sockfds[fd]->cmdline, &connfd, NULL))) {
            close(connfd);
          }
        }
        break;
      }
      case STATE_TLS_ACCEPTING: {
        ret = handle_tls_accepting(fd);
        break;
      }
      case STATE_TLS_SERVER_HANDSHAKING: {
        if ((ret = handle_tls_server_handshaking(fd)) == -1 &&
            errno == EAGAIN) {
          continue;
        } else if (ret == 0) {
          PRINT_DEBUG("TLS connection accepted on fd: %d", fd)
          ret = send_child(sockfds[fd]->cmdline, &fd, NULL);
        }
        break;
      }
      case STATE_TCP_CONNECTING: {
        if (events & (EPOLLERR | EPOLLHUP)) {
          sprintf(errmsg, "TCP connection failed to remote host");
          ret = -1;
        } else {
          ret = send_child(sockfds[fd]->cmdline, &fd, NULL);
        }
        break;
      }
      case STATE_TLS_CONNECTING: {
        if (events & (EPOLLERR | EPOLLHUP)) {
          sprintf(errmsg, "TCP connection failed to remote host");
          ret = -1;
        } else {
          ret = handle_tls_connecting(fd);
        }
        break;
      }
      case STATE_TLS_CLIENT_HANDSHAKING: {
        ret = handle_tls_client_handshaking(fd);
        break;
      }
      case STATE_KTLS_CLIENT_RECV_TICKET1: {
        if ((ret = ktls_recv_ticket(fd)) == -1 && errno == EAGAIN) {
          continue;
        } else if (ret == 0) {
          sockfds[fd]->state = STATE_KTLS_CLIENT_RECV_TICKET2;
          PRINT_DEBUG("fd %d -> STATE_KTLS_CLIENT_RECV_TICKET2", fd);
        }
        break;
      }
      case STATE_KTLS_CLIENT_RECV_TICKET2: {
        if ((ret = ktls_recv_ticket(fd)) == -1 && errno == EAGAIN) {
          continue;
        } else if (ret == 0) {
          PRINT_DEBUG("TLS connection established on fd: %d", fd)
          ret = send_child(sockfds[fd]->cmdline, &fd, NULL);
        }
        break;
      }
      default: {
        PRINT_FATAL("state not implemented: %d", sockfds[fd]->state);
        goto error_cleanup;
      }
    }
    if (ret != 0) {
      if (ERR_peek_error()) {
        ERR_print_errors_fp(stderr);
      }
      if (ret == -1 && errno != 0) {
        PRINT_FATAL("errno: %d (%s)", errno, strerror(errno));
      }
      if (errmsg[0] != '\0') {
        PRINT_FATAL("errmsg: %s", errmsg);
      }
      if (sockfds[fd] != NULL) {  // can respond with error
        // if (errmsg[0] == '\0' && ret == -1 && errno != 0) {
        //   strcpy(errmsg, strerror(errno));
        // }
        send_child(sockfds[fd]->cmdline, NULL, errmsg);
        ret = 0;  // don't crash
      }
    }
  }

  return 0;

error_cleanup:
  global_cleanup();
  return ret;
}

int ktls_global_init(int fd, time_t _poll_period_millis, int _verbosity) {
  childfd = fd;
  verbosity = _verbosity;
  poll_period_millis = _poll_period_millis;

  // establish the default sock flags
  int testfd = sockfd_socket();
  default_sockfd_flags = fcntl(testfd, F_GETFL, 0);
  if (default_sockfd_flags == -1) {
    PRINT_FATAL("fcntl(%d, F_GETFL) failed", testfd);
    goto error_cleanup;
  }
  close(testfd);

  assert(epollfd == -1);
  epollfd = epoll_create1(0);
  if (epollfd == -1) {
    goto error_cleanup;
  }

  // initialize client context
  assert(client_ctx == NULL);
  client_ctx = SSL_CTX_new(TLS_client_method());
  if (client_ctx == NULL) {
    goto error_cleanup;
  }
  SSL_CTX_set_verify(client_ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_options(client_ctx, SSL_OP_ENABLE_KTLS);
  SSL_CTX_set_options(client_ctx, SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
  if (!SSL_CTX_set_cipher_list(client_ctx, ktls12_cipher_list)) {
    goto error_cleanup;
  }
  if (!SSL_CTX_set_ciphersuites(client_ctx, ktls13_cipher_suites)) {
    goto error_cleanup;
  }

  // SSL_CTX_set_max_early_data(client_ctx, 0);

  char* cachain = getenv("TINIKTLS_CA_CHAIN");
  if (cachain != NULL &&
      !SSL_CTX_load_verify_locations(client_ctx, cachain, NULL)) {
    goto error_cleanup;
  } else if (cachain == NULL && !SSL_CTX_set_default_verify_paths(client_ctx)) {
    goto error_cleanup;
  }

  assert(server_ctx == NULL);
  server_ctx = SSL_CTX_new(TLS_server_method());
  if (server_ctx == NULL) {
    goto error_cleanup;
  }
  SSL_CTX_set_options(server_ctx, SSL_OP_ENABLE_KTLS);
  SSL_CTX_set_options(server_ctx, SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
  if (!SSL_CTX_set_cipher_list(server_ctx, ktls12_cipher_list)) {
    goto error_cleanup;
  }
  if (!SSL_CTX_set_ciphersuites(server_ctx, ktls13_cipher_suites)) {
    goto error_cleanup;
  }

  ktls_sockfd_t childsockfd = {.state = STATE_CHILDFD};
  if (sockfd_open(childfd, EPOLLIN | EPOLLET, &childsockfd)) {
    PRINT_FATAL("sockfd_open(%d) failed", childfd);
    goto error_cleanup;
  }

  return 0;

error_cleanup:
  global_cleanup();
  return -1;
}
