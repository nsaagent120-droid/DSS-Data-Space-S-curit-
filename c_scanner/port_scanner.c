/**
 * ============================================================================
 *  DSS Security - Scanner de Ports Réseau Haute Performance en C
 * ============================================================================
 *  Fichier     : c_scanner/port_scanner.c
 *  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
 *  Description : Scanner TCP multi-threadé avec sockets non-bloquants (select)
 *                et capture de bannières (banner grabbing).
 *  Compilation : gcc -O2 -pthread port_scanner.c -o port_scanner
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/time.h>
#include <errno.h>

/* Couleurs ANSI pour le terminal */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_BOLD          "\x1b[1m"
#define ANSI_DIM           "\x1b[2m"

/* Configuration par défaut */
#define DEFAULT_THREADS    50
#define DEFAULT_TIMEOUT_MS 1000
#define MAX_BANNER_LEN     128

/* Structure d'identification de service connu */
typedef struct {
    int port;
    const char *service;
} ServiceEntry;

static const ServiceEntry KNOWN_SERVICES[] = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {111, "RPCBind"},
    {135, "MSRPC"},
    {139, "NetBIOS"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {445, "SMB"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1433, "MSSQL"},
    {1521, "Oracle DB"},
    {2049, "NFS"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {5432, "PostgreSQL"},
    {6379, "Redis"},
    {8080, "HTTP-Proxy/Tomcat"},
    {8443, "HTTPS-Alt"},
    {9000, "PHP-FPM/SonarQube"},
    {9200, "Elasticsearch"},
    {27017, "MongoDB"},
    {0, NULL}
};

/* Structure partagée entre les threads */
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    char target_host[256];
    int start_port;
    int end_port;
    int current_port;
    int timeout_ms;
    int grab_banners;
    int open_ports_count;
    pthread_mutex_t lock;
} ScanConfig;

/* Retourne le nom d'un service standard associé à un port */
const char* get_service_name(int port) {
    for (int i = 0; KNOWN_SERVICES[i].service != NULL; i++) {
        if (KNOWN_SERVICES[i].port == port) {
            return KNOWN_SERVICES[i].service;
        }
    }
    return "Inconnu";
}

/* Tentative de capture de la bannière sur un port ouvert */
void grab_banner(const char *ip, int port, int timeout_ms, char *buffer, size_t max_len) {
    buffer[0] = '\0';
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    /* Timeout sur le socket */
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        /* Envoi d'une sonde générique HTTP ou retour chariot */
        if (port == 80 || port == 8080 || port == 8000) {
            const char *http_req = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, http_req, strlen(http_req), 0);
        } else {
            const char *probe = "\r\n";
            send(sock, probe, strlen(probe), 0);
        }

        char temp[256];
        ssize_t bytes = recv(sock, temp, sizeof(temp) - 1, 0);
        if (bytes > 0) {
            temp[bytes] = '\0';
            /* Nettoyer les sauts de ligne */
            for (ssize_t i = 0; i < bytes; i++) {
                if (temp[i] == '\r' || temp[i] == '\n') {
                    temp[i] = ' ';
                }
            }
            snprintf(buffer, max_len, "%s", temp);
        }
    }
    close(sock);
}

/* Test de connexion non-bloquante avec select() pour un timeout précis */
int scan_port_nonblocking(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    /* Passer le socket en mode non-bloquant */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    int res = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (res == 0) {
        close(sock);
        return 1; /* Port ouvert immédiatement */
    }

    if (errno == EINPROGRESS) {
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel_res = select(sock + 1, NULL, &write_fds, NULL, &tv);
        if (sel_res > 0) {
            int sock_error = 0;
            socklen_t len = sizeof(sock_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &sock_error, &len) == 0) {
                if (sock_error == 0) {
                    close(sock);
                    return 1; /* Connexion établie avec succès */
                }
            }
        }
    }

    close(sock);
    return 0;
}

/* Fonction exécutée par chaque thread ouvrier (worker) */
void* worker_thread(void *arg) {
    ScanConfig *cfg = (ScanConfig*)arg;

    while (1) {
        int port = 0;

        /* Section critique : récupération du prochain port à scanner */
        pthread_mutex_lock(&cfg->lock);
        if (cfg->current_port <= cfg->end_port) {
            port = cfg->current_port++;
        }
        pthread_mutex_unlock(&cfg->lock);

        if (port == 0) {
            break; /* Tous les ports ont été traités */
        }

        if (scan_port_nonblocking(cfg->target_ip, port, cfg->timeout_ms)) {
            char banner[MAX_BANNER_LEN] = "";
            if (cfg->grab_banners) {
                grab_banner(cfg->target_ip, port, cfg->timeout_ms, banner, sizeof(banner));
            }

            pthread_mutex_lock(&cfg->lock);
            cfg->open_ports_count++;
            const char *srv = get_service_name(port);
            printf("%-8d/tcp   " ANSI_COLOR_GREEN "%-10s" ANSI_COLOR_RESET " %-20s " ANSI_DIM "%s" ANSI_COLOR_RESET "\n",
                   port, "OUVERT", srv, banner);
            fflush(stdout);
            pthread_mutex_unlock(&cfg->lock);
        }
    }

    return NULL;
}

/* Résolution DNS vers IPv4 */
int resolve_hostname(const char *hostname, char *ip_str) {
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        return 0;
    }
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        strcpy(ip_str, inet_ntoa(*addr_list[0]));
        return 1;
    }
    return 0;
}

void print_banner(void) {
    printf(ANSI_COLOR_CYAN ANSI_BOLD "\n");
    printf("  ==============================================================\n");
    printf("     DSS C-PORT-SCANNER - Scanner Réseau Multi-Threadé en C     \n");
    printf("     Cybersecurity Mastery Roadmap - Programmation Système      \n");
    printf("  ==============================================================\n" ANSI_COLOR_RESET);
}

void print_usage(const char *prog_name) {
    printf("Usage : %s -t <cible> [options]\n\n", prog_name);
    printf("Options :\n");
    printf("  -t <host/IP>   Cible à scanner (nom de domaine ou IP, ex: 127.0.0.1)\n");
    printf("  -s <port>      Port de départ (défaut : 1)\n");
    printf("  -e <port>      Port de fin (défaut : 1024)\n");
    printf("  -w <threads>   Nombre de threads ouvriers (défaut : %d)\n", DEFAULT_THREADS);
    printf("  -T <ms>        Timeout de connexion en millisecondes (défaut : %d ms)\n", DEFAULT_TIMEOUT_MS);
    printf("  -b             Activer la capture de bannières (banner grabbing)\n");
    printf("  -h             Afficher cette aide\n\n");
    printf("Exemple :\n");
    printf("  %s -t 127.0.0.1 -s 1 -e 1000 -w 100 -b\n\n", prog_name);
}

int main(int argc, char *argv[]) {
    print_banner();

    ScanConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.start_port = 1;
    cfg.end_port = 1024;
    cfg.timeout_ms = DEFAULT_TIMEOUT_MS;
    cfg.grab_banners = 0;
    cfg.open_ports_count = 0;
    int num_threads = DEFAULT_THREADS;

    int opt;
    while ((opt = getopt(argc, argv, "t:s:e:w:T:bh")) != -1) {
        switch (opt) {
            case 't':
                strncpy(cfg.target_host, optarg, sizeof(cfg.target_host) - 1);
                break;
            case 's':
                cfg.start_port = atoi(optarg);
                break;
            case 'e':
                cfg.end_port = atoi(optarg);
                break;
            case 'w':
                num_threads = atoi(optarg);
                break;
            case 'T':
                cfg.timeout_ms = atoi(optarg);
                break;
            case 'b':
                cfg.grab_banners = 1;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (strlen(cfg.target_host) == 0) {
        printf(ANSI_COLOR_RED "[!] Erreur : Veuillez spécifier une cible avec -t <cible>\n" ANSI_COLOR_RESET);
        print_usage(argv[0]);
        return 1;
    }

    if (cfg.start_port < 1 || cfg.end_port > 65535 || cfg.start_port > cfg.end_port) {
        printf(ANSI_COLOR_RED "[!] Erreur : Plage de ports invalide (%d - %d)\n" ANSI_COLOR_RESET, cfg.start_port, cfg.end_port);
        return 1;
    }

    printf(ANSI_COLOR_CYAN "[*] Résolution de la cible '%s'...\n" ANSI_COLOR_RESET, cfg.target_host);
    if (!resolve_hostname(cfg.target_host, cfg.target_ip)) {
        printf(ANSI_COLOR_RED "[!] Erreur : Impossible de résoudre l'adresse de '%s'\n" ANSI_COLOR_RESET, cfg.target_host);
        return 1;
    }

    cfg.current_port = cfg.start_port;
    pthread_mutex_init(&cfg.lock, NULL);

    int total_ports = cfg.end_port - cfg.start_port + 1;
    if (num_threads > total_ports) num_threads = total_ports;
    if (num_threads < 1) num_threads = 1;

    printf(ANSI_COLOR_GREEN "[+] Cible résolue : %s (%s)\n" ANSI_COLOR_RESET, cfg.target_host, cfg.target_ip);
    printf(ANSI_COLOR_CYAN "[*] Plage de ports : %d à %d (%d ports)\n" ANSI_COLOR_RESET, cfg.start_port, cfg.end_port, total_ports);
    printf(ANSI_COLOR_CYAN "[*] Threads : %d | Timeout : %d ms | Banner Grabbing : %s\n\n" ANSI_COLOR_RESET,
           num_threads, cfg.timeout_ms, cfg.grab_banners ? "Actif" : "Inactif");

    printf(ANSI_BOLD "%-12s %-10s %-20s %s\n" ANSI_COLOR_RESET, "PORT", "ÉTAT", "SERVICE", "BANNIÈRE");
    printf("------------------------------------------------------------------------\n");

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    /* Création du pool de threads */
    pthread_t *threads = (pthread_t*)malloc(sizeof(pthread_t) * num_threads);
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &cfg);
    }

    /* Attente de la fin de tous les threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("------------------------------------------------------------------------\n");
    printf(ANSI_COLOR_GREEN "[+] Scan terminé en %.2f secondes.\n" ANSI_COLOR_RESET, elapsed);
    printf(ANSI_COLOR_GREEN "[+] Total de ports ouverts découverts : %d\n\n" ANSI_COLOR_RESET, cfg.open_ports_count);

    free(threads);
    pthread_mutex_destroy(&cfg.lock);

    return 0;
}
