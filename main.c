/*
 * main.c — sha256sum-like CLI tool using mmap.
 *
 * Usage: sha256 <filename>
 * Output: <hex_hash>  <filename>
 *
 * Uses mmap to map the entire file into memory and hashes in a single
 * call to sha256(). Handles the empty file edge case (mmap fails on
 * size 0 on some systems).
 */

#include "sha256.h"

#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror(filename);
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    size_t size = (size_t)st.st_size;
    uint8_t hash[32];

    if (size == 0) {
        /* Empty file — mmap may fail with size 0, hash directly */
        sha256(NULL, 0, hash);
    } else {
        void *mapped = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (mapped == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return 1;
        }

        sha256((const uint8_t *)mapped, size, hash);

        munmap(mapped, size);
    }

    close(fd);

    /* Output format: lowercase hex hash, two spaces, filename */
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("  %s\n", filename);

    return 0;
}
