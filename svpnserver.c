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

SSL* setupTLSServer()
{
	SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;
    int err;

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
    ssl = SSL_new(ctx);

    return ssl;
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

int fork_listen_tun(int tunfd)
{
	if (fork() == 0)
	{
		system("sudo ifconfig tun0 192.168.53.1/24 up && sudo sysctl net.ipv4.ip_forward=1");

		int len;
		do {
			char buf[BUF_LEN];
			bzero(buf, BUF_LEN);
			len = read(tunfd, buf, BUF_LEN);
			printf("Receive TUN: %d\n", len);
			if (len >= 20 && ((buf[0] & 0xF0) == 0x40)) // IPv4
			{
				printf("Receive TUN IPv4: %d | ip.des = 192.168.53.%d\n", len, (int)buf[19]);
				char pipe_file[10];
	            sprintf(pipe_file, "./pipe/%d", (int) buf[19]);
	            int pipefd = open(pipe_file, O_WRONLY);
	            if (pipefd == -1)
	            {
	                printf("File %s is not exist.\n", pipe_file);
	            }
	            else
	            {
	                write(pipefd, buf, len);
	            }
			}
		} while (len > 0);

		return 0;
	}
	else
	{
		return 1;
	}
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

int fork_listen_pipe(char *pipe_file, SSL *ssl)
{
	if (fork() == 0)
	{
		int pipefd = open(pipe_file, O_RDONLY);

		int len;
		do {
			char buf[BUF_LEN];
			bzero(buf, BUF_LEN);
			len = read(pipefd, buf, BUF_LEN);
			SSL_write(ssl, buf, len);
			printf("Read PIPE: %d\n", len);
		} while (len > 0);
		
		remove(pipe_file);

		return 0;
	}
	else
	{
		return 1;
	}
}

int main(int argc, char *argv[])
{
	// pipe folder init
    system("rm -rf pipe");
    mkdir("pipe", 0666);

	int listen_sock = setupTCPServer();
	SSL *ssl = setupTLSServer();

	int tunfd = createTunDevice();
	if (fork_listen_tun(tunfd) == 0) return 0;


	struct sockaddr_in sa_client;
	int lenaddr = sizeof(struct sockaddr_in *);
	while (1)
	{
		printf("TCP listen\n");
		int sock = accept(listen_sock, (struct sockaddr *)&sa_client, &lenaddr); // block
		CHK_ERR(sock, "accept");
		if (fork() == 0)
		{
			close(listen_sock);
			printf("TCP connect\n");

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

	            // check IP and create pipe file
	            char pipe_file[10];
	            sprintf(pipe_file, "./pipe/%s", last_ip_buf);
	            if (mkfifo(pipe_file, 0666) == -1)
	            {
	                printf("This IP(192.168.53.%s) has been occupied.\n", last_ip_buf);
	            }
	            else
	            {
	            	if (fork_listen_pipe(pipe_file, ssl) == 0) return 0;

		            /*----------------Receive SSL ------------------------------*/
					int len;
					do {
						char buf[BUF_LEN];
						len = SSL_read(ssl, buf, BUF_LEN);
						buf[len] = '\0';
						write(tunfd, buf, len);
						printf("Receive SSL: %d\n", len);
					} while (len > 0);

					remove(pipe_file);
	            }
            }
            else
            {
            	printf("Login failed!\n");
            }
			
			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(sock);
			printf("SSL shutdown.\n");

			return 0;
		}
		else
		{
			close(sock);
		}
	}

	return 0;
}
