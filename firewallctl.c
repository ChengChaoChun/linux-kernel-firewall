#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>

#define FIREWALL_PROC_PATH "/proc/firewall"
#define BUFFER_SIZE 256

static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s add <IPv4>\n"
            "  %s del <IPv4>\n"
            "  %s list\n",
            program, program, program);
}

static int validate_ipv4(const char *ip)  
{
    struct in_addr addr;

    if (ip == NULL)
        return 0;

    return inet_pton(AF_INET, ip, &addr) == 1;
}

/*
 * Add or remove a blocked IP.
 * command: '+' means add, '-' means delete
 */
static int modify_ip(char command, const char *ip)
{
    int fd;
    int ret;
    char buffer[INET_ADDRSTRLEN + 2];
    size_t len;
    size_t written = 0;

    if (!validate_ipv4(ip)) {
        fprintf(stderr, "Error: invalid IPv4 address: %s\n", ip);
        return -1;
    }

    /*
     * Construct the command expected by /proc/firewall.
     *
     * Example:
     *   +192.168.1.30\n
     *   -192.168.1.30\n
     */
    ret = snprintf(buffer, sizeof(buffer), "%c%s\n", command, ip);

    if (ret < 0 || (size_t)ret >= sizeof(buffer)) {
        fprintf(stderr, "Error: failed to format command\n");
        return -1;
    }

    len = (size_t)ret;

    /* Open the procfs entry for writing */
    fd = open(FIREWALL_PROC_PATH, O_WRONLY);

    if (fd < 0) {
        perror("Error: cannot open " FIREWALL_PROC_PATH);
        fprintf(stderr,
                "Make sure the firewall kernel module is loaded "
                "and run this command with sufficient privileges.\n");
        return -1;
    }

    /*
     * Write the complete command.
     *
     * write() may write fewer bytes than requested,
     * so handle partial writes.
     */
    while (written < len) {
        ssize_t n = write(fd, buffer + written, len - written);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            perror("Error: write failed");
            close(fd);
            return -1;
        }

        if (n == 0) {
            fprintf(stderr, "Error: write returned 0\n");
            close(fd);
            return -1;
        }

        written += (size_t)n;
    }

    if (close(fd) < 0) {
        perror("Error: close failed");
        return -1;
    }

    if (command == '+') {
        printf("Successfully added blocked IP: %s\n", ip);
    } else {
        printf("Successfully removed blocked IP: %s\n", ip);
    }

    return 0;
}
  
/* Display all blocked IPs */
static int list_ips(void)
{
    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t n;
    int found = 0;

    /* Open the procfs entry for reading */
    fd = open(FIREWALL_PROC_PATH, O_RDONLY);

    if (fd < 0) {
        perror("Error: cannot open " FIREWALL_PROC_PATH);
        fprintf(stderr,
                "Make sure the firewall kernel module is loaded "
                "and run this command with sufficient privileges.\n");
        return -1;
    }

    printf("Blocked IP list:\n");

    /*
     * Read until EOF.
     */
    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        size_t i;

        /*
         * Check whether the returned data contains
         * any non-whitespace character.
         */
        for (i = 0; i < (size_t)n; i++) {
            if (!isspace((unsigned char)buffer[i])) {
                found = 1;
                break;
            }
        }

        if (fwrite(buffer, 1, (size_t)n, stdout) != (size_t)n) {
            perror("Error: stdout write failed");
            close(fd);
            return -1;
        }
    }

    if (n < 0) {
        perror("Error: read failed");
        close(fd);
        return -1;
    }

    if (close(fd) < 0) {
        perror("Error: close failed");
        return -1;
    }

    if (!found)
        printf("No blocked IPs.\n");

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
  
    /* Add a blocked IP */
    if (strcmp(argv[1], "add") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        return modify_ip('+', argv[2]) == 0
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    /* Remove a blocked IP */
    if (strcmp(argv[1], "del") == 0) {
        if (argc != 3) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        return modify_ip('-', argv[2]) == 0
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    /* List all blocked IPs */
    if (strcmp(argv[1], "list") == 0) {
        if (argc != 2) {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        return list_ips() == 0
                   ? EXIT_SUCCESS
                   : EXIT_FAILURE;
    }

    /* Unknown command */
    fprintf(stderr, "Error: unknown command '%s'\n", argv[1]);
    print_usage(argv[0]);    

    return EXIT_FAILURE;
}