#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define BUF_LEN 2048
#define CA_DIR "./ca_client"
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_LEN(len,s) if ((len) < 1) { perror(s); exit(1); }

int setupTCPClient(const char* hostname, int port)
{
    struct sockaddr_in server_addr;

    // Get the IP address from hostname
    struct hostent *hp = gethostbyname(hostname);

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // Fill in the destination information (IP, port #, and family)
    memset(&server_addr, 0, sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    // Connect to the destination
    int err = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    CHK_ERR(err, "connect");

    return sockfd;
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = (SSL_METHOD *)TLSv1_2_method();
    ctx = SSL_CTX_new(meth);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1)
    {
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

int createTunDevice()
{
    int tunfd, err;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        printf("open tun error. errno = %d\n", errno);
        return tunfd;
    }

    err = ioctl(tunfd, TUNSETIFF, &ifr);
    CHK_ERR(err, "ioctl");

    return tunfd;
}

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        printf("Missing args.\n");
        exit(1);
    }

    char *hostname = argv[1], *username = argv[3], *password = argv[4], *last_ip = argv[5];
    int port = atoi(argv[2]);

    /*----------------Create a TCP connection ------------------*/
    int sockfd = setupTCPClient(hostname, port);
    printf("TCP connect.\n");

    /*----------------TLS initialization -----------------------*/
    SSL *ssl = setupTLSClient(hostname);

    /*----------------TLS handshake ----------------------------*/
    SSL_set_fd(ssl, sockfd);
    int err = SSL_connect(ssl);
    CHK_SSL(err);
    printf("SSL connection is successful. Using %s\n", SSL_get_cipher(ssl));

    /*----------------Authenticating client by user/passwd -----*/
    SSL_write(ssl, username, strlen(username)); // username
    SSL_write(ssl, password, strlen(password)); // password
    SSL_write(ssl, last_ip, strlen(last_ip)); // local last IP

    /*----------------Create TUN -------------------------------*/
    int tunfd = createTunDevice();

    /*----------------Add routing ------------------------------*/
    char cmd[100];
    sprintf(cmd, "sudo ifconfig tun0 192.168.53.%s/24 up && sudo route add -net 192.168.60.0/24 tun0", last_ip);
    system(cmd);

    fd_set read_set;
    FD_ZERO(&read_set);

    while (1)
    {
        FD_SET(tunfd, &read_set);
        FD_SET(sockfd, &read_set);
        int fd = select(tunfd + 1, &read_set, NULL, NULL, NULL);
        CHK_ERR(fd, "select");
        if (FD_ISSET(tunfd, &read_set))
        {
            char buf[BUF_LEN];
            bzero(buf, BUF_LEN);
            int len = read(tunfd, buf, BUF_LEN);
            printf("Receive TUN: %d\n", len);
            if (len >= 20 && ((buf[0] & 0xF0) == 0x40)) // IPv4
            {
                if ((int)buf[15] == atoi(last_ip)) // ip.src == 192.168.53.last_ip
                {
                    printf("SSL write: %d\n", len);
                    SSL_write(ssl, buf, len);
                }
            }
            CHK_LEN(len, "Close TUN.");
        }
        if (FD_ISSET(sockfd, &read_set))
        {
            /*----------------Receive SSL ------------------------------*/
            char buf[BUF_LEN];
            int len = SSL_read(ssl, buf, BUF_LEN);
            write(tunfd, buf, len);
            printf("Receive SSL: %d\n", len);
            CHK_LEN(len, "Close SSL.");
        }
    }

    return 0;
}