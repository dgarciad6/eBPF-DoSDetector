#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#define DEFAULT_MAP_NAME "dos_detector"
#define DEFAULT_OBJ_FILE "alertDoS.o"

void log_attacker_ip(__u32 ip) {
    struct in_addr ip_addr = { .s_addr = ip };
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

    printf("[!] Posible ataque DoS detectado desde IP: %s\n", ip_str);

    FILE *log = fopen("dos_log.txt", "a");
    FILE *backup = fopen("ips_detectadas.txt", "a");

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

char* get_map_path(const char *mode, const char *map_name) {
    static char path[256];
    if (strcmp(mode, "xdp") == 0) {
        snprintf(path, sizeof(path), "/sys/fs/bpf/xdp/globals/%s", map_name);
    } else {
        snprintf(path, sizeof(path), "/sys/fs/bpf/tc/globals/%s", map_name);
    }

    return path;
}

int pin_map_if_needed(const char *mode, const char *map_name, const char *obj_file) {
    const char *map_path = get_map_path(mode, map_name);
    int map_fd = bpf_obj_get(map_path);
    if (map_fd >= 0) {
        return map_fd;
    }

    printf("[*] Mapa no encontrado en '%s'. Intentando pinnear desde %s...\n", map_path, obj_file);

    struct bpf_object *obj;
    struct bpf_map *map;
    int err;

    obj = bpf_object__open_file(obj_file, NULL);
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
        if (strcmp(bpf_map__name(map), map_name) == 0) {
            err = bpf_map__pin(map, map_path);
            if (err) {
                fprintf(stderr, "Error pinneando el mapa: %s\n", strerror(errno));
                return -1;
            }
            return bpf_map__fd(map);
        }
    }

    fprintf(stderr, "No se encontró el mapa '%s' en el objeto.\n", map_name);
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Uso: %s <modo: tc|xdp> <map_name> <obj_file>\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *map_name = argv[2];
    const char *obj_file = argv[3];

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int map_fd = pin_map_if_needed(mode, map_name, obj_file);
    if (map_fd < 0) {
        fprintf(stderr, "No se pudo obtener ni pinnear el mapa.\n");
        return 1;
    }

    printf("[*] Monitoreando mapa '%s' en modo '%s'...\n", map_name, mode);

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
