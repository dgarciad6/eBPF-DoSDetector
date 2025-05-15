#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <time.h>

#define MAP_PATH "/sys/fs/bpf/tc/globals/dos_detector"
#define IP_BACKUP_LOG "ips_detectadas.txt"
#define BPF_OBJ_FILE "alertDoS.o"

void log_attacker_ip(__u32 ip) {
    struct in_addr ip_addr = { .s_addr = ip };
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

    printf("[!] Posible ataque DoS detectado desde IP: %s\n", ip_str);

    FILE *log = fopen("dos_log.txt", "a");
    FILE *backup = fopen(IP_BACKUP_LOG, "a");

    if (log) {
        time_t now = time(NULL);
        fprintf(log, "%s - DoS desde IP: %s\n", ctime(&now), ip_str);
        fclose(log);
    }

    if (backup) {
        fprintf(backup, "%s\n", ip_str);
        fclose(backup);
    }
}

int pin_map_if_needed() {
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd >= 0) {
        return map_fd; // Ya está pinneado
    }

    printf("[*] Mapa no encontrado. Intentando pinnear desde el objeto BPF...\n");

    struct bpf_object *obj;
    struct bpf_map *map;
    int err;

    obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error abriendo el objeto BPF: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error cargando el objeto BPF: %s\n", strerror(-err));
        return -1;
    }

    bpf_object__for_each_map(map, obj) {
        if (strcmp(bpf_map__name(map), "dos_detector") == 0) {
            err = bpf_map__pin(map, MAP_PATH);
            if (err) {
                fprintf(stderr, "Error pinneando el mapa: %s\n", strerror(errno));
                return -1;
            }
            return bpf_map__fd(map);
        }
    }

    fprintf(stderr, "No se encontró el mapa 'dos_detector' en el objeto.\n");
    return -1;
}

int main() {
    int map_fd;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    map_fd = pin_map_if_needed();
    if (map_fd < 0) {
        fprintf(stderr, "No se pudo obtener ni pinnear el mapa.\n");
        return 1;
    }

    printf("[*] Monitoreando mapa de detección DoS en tiempo real...\n");

    while (1) {
        __u32 key = 0, next_key;
        __u64 value;

        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                log_attacker_ip(next_key);
                bpf_map_delete_elem(map_fd, &next_key);
            }
            key = next_key;
        }

        sleep(1);
    }

    close(map_fd);
    return 0;
}
