#include <stdio.h>
#include <string.h>

#define N 256

/* 
Simple program that writes a string to a file and then reads it back.
*/
int main() {
    FILE *file;
    char buffer[N] = {0};
    const char *filename = "output.txt";

    strcpy(buffer, "Zxylo123\n");

    printf("1. Open %s to write:\n%s\n", filename, buffer);
    file = fopen(filename, "w+");
    if (file == NULL) {
        perror("Error opening file for writing");
        return 1;
    }

    fprintf(file, "%s", buffer);
    fclose(file);

    printf("2. Open %s to read:\n", filename);
    file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file for reading");
        return 1;
    }

    memset(buffer, 0, sizeof(buffer));

    if (fgets(buffer, sizeof(buffer), file) == NULL) {
        perror("Error reading file");
        fclose(file);
        return 1;
    }

    puts(buffer);
    fclose(file);

    return 0;
}
