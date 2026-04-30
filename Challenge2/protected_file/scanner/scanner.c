#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define N 512

int main(int argc, char *argv[]) {

    char default_file[N];
    memset(default_file, 0, N);
    if (argc < 2) {
        printf("No file provided, exiting: usage: %s <file_to_scan>\n", argv[0]);
        return 1;
    } else {
        printf("Using provided file: %s\n", argv[1]);
        strncpy(default_file, argv[1], strlen(argv[1]) < N ? strlen(argv[1]) : N-1);
        default_file[N-1] = '\0'; // Ensure null-termination
    }

    /* READ PHASE */
    char buffer[256];
    FILE * file = fopen(default_file, "r");
    if (file == NULL) {
        perror("Error opening file for reading");
        return 1;
    }
    while (fgets(buffer, sizeof(buffer), file)) {
        printf("Read: %s", buffer);
    }
    fclose(file);

    /* WRITE PHASE */
    file = fopen(default_file, "w");
    if (file == NULL) {
        perror("Error when trying to write");
    }else{
        int ret = fprintf(file, "You have been pwned!\n");
        if (ret < 0) {
            perror("Error when trying to write");
        }
        fclose(file);
    }

    // Read the file again to confirm the write
    file = fopen(default_file, "r");
    if (file == NULL) {
        perror("Error opening file for reading");
        return 1;
    }
    while (fgets(buffer, sizeof(buffer), file)) {
        printf("Read after write: %s", buffer);
    }
    fclose(file);

}
