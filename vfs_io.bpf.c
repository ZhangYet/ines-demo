//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

volatile const u32 target = 0;

enum IO_TYPE {
    READ,
    WRITE,
};

struct io_stat {
    unsigned int time;
    size_t size;
};

struct io_key {
    enum IO_TYPE type;
    u32 pid;
    u32 fd;
};

struct io_stat *unused_event __attribute__((unused));
struct io_key *unused_key __attribute__((unused));

struct bpf_map_def SEC("maps") ines_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct io_key),
    .value_size = sizeof(struct io_stat),
    .max_entries = 1024,
};


inline int probe_func(unsigned int fd, char* buf, size_t count, enum IO_TYPE type) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    if ( pid != target && target != 0 )
        return 0;

    struct io_key key = {
        .type = type,
        .pid = pid,
        .fd = fd,
    };

    struct io_stat *stat = bpf_map_lookup_elem(&ines_map, &key);
    if (stat) {
        stat->time ++;
        stat->size += count;
        return 0;
    }

    struct io_stat s = {
        .time = 1,
        .size = count,
    };

    bpf_map_update_elem(&ines_map, &key, &s, 0);
    return 0;

}

SEC("kprobe/ksys_write")
int BPF_KPROBE(vfs_write_probe, unsigned int fd, const char *buf, size_t count)
{
    return probe_func(fd, buf, count, WRITE);
}

SEC("kprobe/ksys_read")
int BPF_KPROBE(vfs_read_probe, unsigned int fd, const char *buf, size_t count)
{
    return probe_func(fd, buf, count, READ);
}