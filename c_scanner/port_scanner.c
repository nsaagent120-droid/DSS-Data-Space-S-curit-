/**
 * ============================================================================
 *  DSS Security - Scanner Réseau Haute Performance en C (D-Scan C Engine)
 * ============================================================================
 *  Fichier     : c_scanner/port_scanner.c
 *  Auteur      : DSS Security / Cybersecurity Mastery Roadmap
 *  Description : Scanner TCP ultra-rapide avec sockets non-bloquants (select),
 *                multi-threading POSIX (pthread), capture de bannières,
 *                détection de services et export JSON.
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

/* Couleurs ANSI pour terminal */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_BOLD          "\x1b[1m"
#define ANSI_DIM           "\x1b[2m"

#define DEFAULT_THREADS    50
#define DEFAULT_TIMEOUT_MS 800
#define MAX_BANNER_LEN     128
#define MAX_PORTS          65535

/* Structure d'identification de service connu */
typedef struct {
    int port;
    const char *service;
} ServiceEntry;

static const ServiceEntry KNOWN_SERVICES[] = {
    {21, "FTP (File Transfer)"},
    {22, "SSH (Secure Shell)"},
    {23, "Telnet (Non-chiffré)"},
    {25, "SMTP (Mail)"},
    {53, "DNS (Domain Name)"},
    {80, "HTTP (Web)"},
    {110, "POP3"},
    {111, "RPCBind"},
    {135, "MSRPC"},
    {139, "NetBIOS"},
    {143, "IMAP"},
    {443, "HTTPS (TLS/SSL)"},
    {445, "SMB (Windows Share)"},
    {465, "SMTPS"},
    {587, "SMTP Submission"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1433, "Microsoft SQL Server"},
    {1521, "Oracle Database"},
    {2049, "NFS"},
    {3000, "Node.js / Dev Web"},
    {3306, "MySQL / MariaDB"},
    {3389, "RDP (Remote Desktop)"},
    {5000, "Flask / Dev App"},
    {5432, "PostgreSQL Database"},
    {6379, "Redis Key-Value"},
    {8000, "HTTP-Dev"},
    {8080, "HTTP-Proxy / Tomcat"},
    {8443, "HTTPS-Alt"},
    {9000, "SonarQube / PHP-FPM"},
    {9200, "Elasticsearch API"},
    {27017, "MongoDB NoSQL"},
    {0, NULL}
};

/* Liste prédéfinie des 20 ports les plus fréquents */
static const int TOP_20_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443
};
#define TOP_20_COUNT 20

typedef struct {
    int port;
    char status[16];
    char service[64];
    char banner[MAX_BANNER_LEN];
} ScanResult;

/* Structure de configuration globale */
typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    char target_host[256];
    int port_list[MAX_PORTS];
    int total_ports;
    int current_index;
    int timeout_ms;
    int grab_banners;
    
    ScanResult results[4096];
    int open_count;
    pthread_mutex_t lock;
} ScanConfig;

const char* get_service_name(int port) {
    for (int i = 0; KNOWN_SERVICES[i].service != NULL; i++) {
        if (KNOWN_SERVICES[i].port == port) {
            return KNOWN_SERVICES[i].service;
        }
    }
    return "Inconnu";
}

void grab_banner(const char *ip, int port, int timeout_ms, char *buffer, size_t max_len) {
    buffer[0] = '\0';
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
        if (port == 80 || port == 8080 || port == 8000 || port == 3000) {
            const char *http_req = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, http_req, strlen(http_req), 0);
        } else if (port == 22) {
            /* SSH envoie sa bannière automatiquement */
        } else {
            const char *probe = "\r\n";
            send(sock, probe, strlen(probe), 0);
        }

        char temp[256];
        ssize_t bytes = recv(sock, temp, sizeof(temp) - 1, 0);
        if (bytes > 0) {
            temp[bytes] = '\0';
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

int scan_port_nonblocking(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

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
        return 1;
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
                    return 1;
                }
            }
        }
    }

    close(sock);
    return 0;
}

void* worker_thread(void *arg) {
    ScanConfig *cfg = (ScanConfig*)arg;

    while (1) {
        int port = 0;

        pthread_mutex_lock(&cfg->lock);
        if (cfg->current_index < cfg->total_ports) {
            port = cfg->port_list[cfg->current_index++];
        }
        pthread_mutex_unlock(&cfg->lock);

        if (port == 0) {
            break;
        }

        if (scan_port_nonblocking(cfg->target_ip, port, cfg->timeout_ms)) {
            char banner[MAX_BANNER_LEN] = "";
            if (cfg->grab_banners) {
                grab_banner(cfg->target_ip, port, cfg->timeout_ms, banner, sizeof(banner));
            }

            const char *srv = get_service_name(port);

            pthread_mutex_lock(&cfg->lock);
            if (cfg->open_count < 4096) {
                cfg->results[cfg->open_count].port = port;
                snprintf(cfg->results[cfg->open_count].status, sizeof(cfg->results[cfg->open_count].status), "open");
                snprintf(cfg->results[cfg->open_count].service, sizeof(cfg->results[cfg->open_count].service), "%s", srv);
                snprintf(cfg->results[cfg->open_count].banner, sizeof(cfg->results[cfg->open_count].banner), "%s", banner);
                cfg->open_count++;
            }

            printf("%-8d/tcp   " ANSI_COLOR_GREEN "%-10s" ANSI_COLOR_RESET " %-24s " ANSI_DIM "%s" ANSI_COLOR_RESET "\n",
                   port, "OUVERT", srv, banner);
            fflush(stdout);
            pthread_mutex_unlock(&cfg->lock);
        }
    }

    return NULL;
}

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

void export_json(const ScanConfig *cfg, const char *filename) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        printf(ANSI_COLOR_RED "[!] Erreur lors de l'ouverture du fichier JSON %s\n" ANSI_COLOR_RESET, filename);
        return;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"target_host\": \"%s\",\n", cfg->target_host);
    fprintf(f, "  \"target_ip\": \"%s\",\n", cfg->target_ip);
    fprintf(f, "  \"open_ports_count\": %d,\n", cfg->open_count);
    fprintf(f, "  \"ports\": [\n");

    for (int i = 0; i < cfg->open_count; i++) {
        fprintf(f, "    {\n");
        fprintf(f, "      \"port\": %d,\n", cfg->results[i].port);
        fprintf(f, "      \"protocol\": \"tcp\",\n");
        fprintf(f, "      \"status\": \"%s\",\n", cfg->results[i].status);
        fprintf(f, "      \"service\": \"%s\",\n", cfg->results[i].service);
        fprintf(f, "      \"banner\": \"%s\"\n", cfg->results[i].banner);
        fprintf(f, "    }%s\n", (i < cfg->open_count - 1) ? "," : "");
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);
    printf(ANSI_COLOR_GREEN "[+] Rapport JSON exporté avec succès dans : %s\n" ANSI_COLOR_RESET, filename);
}

void print_banner(void) {
    printf(ANSI_COLOR_CYAN ANSI_BOLD "\n");
    printf("  ==============================================================\n");
    printf("     DSS C-PORT-SCANNER v2.0 - Scanner POSIX Ultra-Rapide       \n");
    printf("     Cybersecurity Mastery Roadmap - Programmation Sockets C    \n");
    printf("  ==============================================================\n" ANSI_COLOR_RESET);
}

void print_usage(const char *prog_name) {
    printf("Usage : %s -t <cible> [options]\n\n", prog_name);
    printf("Options :\n");
    printf("  -t <host/IP>   Cible à scanner (ex: 127.0.0.1 ou scanme.nmap.org)\n");
    printf("  -s <port>      Port de départ (défaut : 1)\n");
    printf("  -e <port>      Port de fin (défaut : 1024)\n");
    printf("  -p <preset>    Preset de ports : 'top20' ou 'all'\n");
    printf("  -w <threads>   Nombre de threads simultanés (défaut : %d)\n", DEFAULT_THREADS);
    printf("  -T <ms>        Timeout en millisecondes (défaut : %d ms)\n", DEFAULT_TIMEOUT_MS);
    printf("  -b             Activer la capture de bannières (banner grabbing)\n");
    printf("  -o <json_file> Exporter les résultats au format JSON\n");
    printf("  -h             Afficher cette aide\n\n");
    printf("Exemple :\n");
    printf("  %s -t 127.0.0.1 -s 1 -e 1024 -w 100 -b -o scan.json\n\n", prog_name);
}

int main(int argc, char *argv[]) {
    print_banner();

    ScanConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    int start_p = 1;
    int end_p = 1024;
    int use_top20 = 0;
    cfg.timeout_ms = DEFAULT_TIMEOUT_MS;
    cfg.grab_banners = 0;
    cfg.open_count = 0;
    int num_threads = DEFAULT_THREADS;
    char json_file[256] = "";

    int opt;
    while ((opt = getopt(argc, argv, "t:s:e:p:w:T:bo:h")) != -1) {
        switch (opt) {
            case 't':
                strncpy(cfg.target_host, optarg, sizeof(cfg.target_host) - 1);
                break;
            case 's':
                start_p = atoi(optarg);
                break;
            case 'e':
                end_p = atoi(optarg);
                break;
            case 'p':
                if (strcmp(optarg, "top20") == 0) {
                    use_top20 = 1;
                } else if (strcmp(optarg, "all") == 0) {
                    start_p = 1;
                    end_p = 65535;
                }
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
            case 'o':
                strncpy(json_file, optarg, sizeof(json_file) - 1);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (strlen(cfg.target_host) == 0) {
        printf(ANSI_COLOR_RED "[!] Erreur : Spécifiez une cible avec -t <cible>\n" ANSI_COLOR_RESET);
        print_usage(argv[0]);
        return 1;
    }

    if (use_top20) {
        cfg.total_ports = TOP_20_COUNT;
        for (int i = 0; i < TOP_20_COUNT; i++) {
            cfg.port_list[i] = TOP_20_PORTS[i];
        }
    } else {
        if (start_p < 1 || end_p > 65535 || start_p > end_p) {
            printf(ANSI_COLOR_RED "[!] Erreur : Plage de ports invalide (%d - %d)\n" ANSI_COLOR_RESET, start_p, end_p);
            return 1;
        }
        cfg.total_ports = 0;
        for (int p = start_p; p <= end_p; p++) {
            cfg.port_list[cfg.total_ports++] = p;
        }
    }

    printf(ANSI_COLOR_CYAN "[*] Résolution DNS de '%s'...\n" ANSI_COLOR_RESET, cfg.target_host);
    if (!resolve_hostname(cfg.target_host, cfg.target_ip)) {
        printf(ANSI_COLOR_RED "[!] Erreur : Échec de résolution DNS pour '%s'\n" ANSI_COLOR_RESET, cfg.target_host);
        return 1;
    }

    cfg.current_index = 0;
    pthread_mutex_init(&cfg.lock, NULL);

    if (num_threads > cfg.total_ports) num_threads = cfg.total_ports;
    if (num_threads < 1) num_threads = 1;

    printf(ANSI_COLOR_GREEN "[+] Cible : %s (%s)\n" ANSI_COLOR_RESET, cfg.target_host, cfg.target_ip);
    printf(ANSI_COLOR_CYAN "[*] Total ports à scanner : %d | Threads : %d | Timeout : %d ms\n\n" ANSI_COLOR_RESET,
           cfg.total_ports, num_threads, cfg.timeout_ms);

    printf(ANSI_BOLD "%-12s %-10s %-24s %s\n" ANSI_COLOR_RESET, "PORT", "ÉTAT", "SERVICE", "BANNIÈRE");
    printf("--------------------------------------------------------------------------------\n");

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    pthread_t *threads = (pthread_t*)malloc(sizeof(pthread_t) * num_threads);
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &cfg);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("--------------------------------------------------------------------------------\n");
    printf(ANSI_COLOR_GREEN "[+] Scan terminé en %.2f secondes — %d port(s) ouvert(s).\n\n" ANSI_COLOR_RESET, elapsed, cfg.open_count);

    if (strlen(json_file) > 0) {
        export_json(&cfg, json_file);
    }

    free(threads);
    pthread_mutex_destroy(&cfg.lock);

    return 0;
}
