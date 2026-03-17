#include "../include/storage.h"
#include "../include/tracker.h"
#include "../include/rules.h"
#include <time.h>

volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void print_error(const char *msg)
{
    size_t r = write(2, msg, strlen(msg));
    (void)r;
}

static int check_args(int argc, char **argv)
{
    (void)argv;

    if (argc > 1)
        return 84;
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *links[16] = {0};
    storage_t storage = {0};
    int nb_links = 0;
    struct ring_buffer *rb = NULL;
    int rb_fd = -1;
    int error = 0;
    time_t last_rules_run = time(NULL);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (check_args(argc, argv) == 84)
        return 84;

    if (init_storage(&storage) == 84) {
        print_error("Unsuccessfull creation of storage\n");
        return 84;
    }

    if (init_filters() == 84) {
        print_error("Unsuccessfull initialization of filters\n");
        return 84;
    }

    extern tracker_t tracker;
    storage.tracker = &tracker;

    obj = bpf_object__open_file("edr_bpf.bpf.o", NULL);
    if (obj == NULL) {
        print_error("Error in opening\n");
        return 84;
    }
    error = bpf_object__load(obj);
    if (error < 0) {
        print_error("Error in loading\n");
        return 84;
    }
    
    bpf_object__for_each_program(prog, obj)
    {
        if (nb_links >= 16) {
            print_error("Too many programs\n");
            return 84;
        }
        links[nb_links] = bpf_program__attach(prog);
        if (!links[nb_links]) {
            print_error("Error attaching program\n");
            return 84;
        }
        nb_links++;
    }
    if (nb_links == 0) {
        print_error("No program found\n");
        return 84;
    }

    rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    if (rb_fd < 0) {
        print_error("Error in fd\n");
        return 84;
    }

    rb = ring_buffer__new(rb_fd, handle_event, &storage, NULL);
    if (!rb) {
        print_error("Error in ring buffer\n");
        return 84;
    }

    while (!g_stop) {
        error = ring_buffer__poll(rb, 250);
        if (error == -EINTR)
            break;
        if (error < 0)
            break;
        
        time_t now = time(NULL);

        if (now - last_rules_run >= 1) {
            run_rules(&storage);
            last_rules_run = now;
        }
    }

    ring_buffer__free(rb);
    for (int i = 0; i < nb_links; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    close_storage(&storage);
    return 0;
}