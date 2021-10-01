#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>

#define PORT 4433
#define BUF_LEN 2048
#define CERT_FILE "./cert_server/server-cert-new.pem"
#define KEY_FILE "./cert_server/server-key-new.pem"
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons(PORT);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

SSL_CTX* setupTLSServer()
{
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    //SSL *ssl;

    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Step 2: Set up the server certificate and private key
    SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM);
    // Step 3: Create a new SSL structure for a connection
    //ssl = SSL_new(ctx);

    return ctx;
}

int createTunDevice() {
    int tunfd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

    tunfd = open("/dev/net/tun", O_RDWR);
    int err = ioctl(tunfd, TUNSETIFF, &ifr);
    CHK_ERR(err, "ioctl");

    return tunfd;
}

int login(char *user, char *passwd)
{
    struct spwd *pw;
    char *epasswd;
    pw = getspnam(user);
    if (pw == NULL)
    {
        printf("pw is NULL\n");
        return 0;
    }

    printf("Login name: %s\n", pw->sp_namp);
    printf("Passwd    : %s\n", pw->sp_pwdp);

    epasswd = crypt(passwd, pw->sp_pwdp);
    if (strcmp(epasswd, pw->sp_pwdp))
    {
        printf("Incorrect passwd\n");
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[])
{
    int listen_sock = setupTCPServer();
    SSL_CTX *ctx = setupTLSServer();
    int tunfd = createTunDevice();

    system("sudo ifconfig tun0 192.168.53.1/24 up && sudo sysctl net.ipv4.ip_forward=1");

    fd_set read_set;
    FD_ZERO(&read_set);

    struct sockaddr_in sa_client;
    int lenaddr = sizeof(struct sockaddr_in *);

    int result, fd, len;
    int ip_sock_map[256]; // last_ip -> tcp sockfd
    memset(ip_sock_map, -1, sizeof(int) * 256);
    int fds[FD_SETSIZE]; // active fds
    memset(fds, 0, sizeof(int) * FD_SETSIZE);
    SSL* sock_ssl_map[FD_SETSIZE]; // tcp sockfd -> ssl

    while (1)
    {
        // Set the concerned fds to select()
        FD_SET(listen_sock, &read_set);
        FD_SET(tunfd, &read_set);
        for (fd = 0; fd < FD_SETSIZE; fd++) if (fds[fd] != 0) {FD_SET(fd, &read_set); printf("fds[%d]=%d\n", fd, fds[fd]);}

        result = select(FD_SETSIZE, &read_set, NULL, NULL, NULL);
        if (result < 1)
        {
            perror("select");
            exit(1);
        }

        for (fd = 0; fd < FD_SETSIZE; fd++)
        {
            if (FD_ISSET(fd, &read_set)) // fd is ready
            {
                printf("fd: %d\n", fd);
                if (fd == tunfd) // Receive from TUN and forward to relative SSL connection
                {
                    char buf[BUF_LEN];
                    bzero(buf, BUF_LEN);
                    len = read(tunfd, buf, BUF_LEN);
                    printf("Receive TUN: %d\n", len);
                    if (len >= 20 && ((buf[0] & 0xF0) == 0x40)) // IPv4
                    {
                        printf("Receive TUN IPv4: %d | ip.des = 192.168.53.%d\n", len, (int)buf[19]);
                        int sock = ip_sock_map[(int)buf[19]];
                        if (sock >= 0)
                        {
                            SSL* ssl = sock_ssl_map[sock];
                            SSL_set_fd(ssl, sock);
                            SSL_write(ssl, buf, len);
                        }
                    }
                }
                else if (fd == listen_sock) // Accept TCP/SSL connection and authentication
                {
                    int sock = accept(listen_sock, (struct sockaddr *)&sa_client, &lenaddr); // block
                    CHK_ERR(sock, "accept");
                    printf("TCP connect\n");

                    SSL* ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, sock);
                    int err = SSL_accept(ssl);
                    CHK_SSL(err);
                    printf("SSL connection established!\n");

                    // login messages
                    char user[BUF_LEN], passwd[BUF_LEN], last_ip_buf[BUF_LEN];
                    user[SSL_read(ssl, user, BUF_LEN)] = '\0';
                    passwd[SSL_read(ssl, passwd, BUF_LEN)] = '\0';
                    last_ip_buf[SSL_read(ssl, last_ip_buf, BUF_LEN)] = '\0';

                    if (login(user, passwd))
                    {
                        printf("Login success!\n");
                        int last_ip = atoi(last_ip_buf);
                        ip_sock_map[last_ip] = sock;
                        sock_ssl_map[sock] = ssl;
                        fds[sock] = 1;
                    }
                    else
                    {
                        close(sock);
                        printf("Login failed!\n");
                    }
                }
                else // Common SSL read
                {
                    SSL* ssl = sock_ssl_map[fd];
                    SSL_set_fd(ssl, fd);
                    char buf[BUF_LEN];
                    len = SSL_read(ssl, buf, BUF_LEN);
                    buf[len] = '\0';
                    printf("Receive SSL: %d\n", len);
                    if (len == -1)
                    {
                        CHK_SSL(len);
                    }
                    write(tunfd, buf, len);
                    if (len < 1) 
                    {
                        fds[fd] = 0;
                        FD_CLR(fd, &read_set);
                        close(fd);
                        printf("SSL connection shutdown.\n");
                    }
                }
            }
        }
    }

    //SSL_shutdown(ssl);
    //SSL_free(ssl);

    return 0;
}
