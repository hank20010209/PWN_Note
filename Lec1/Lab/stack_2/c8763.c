#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define MAX_WIDTH 100
#define MAX_HEIGHT 100

void c8763(void) {
    char filename[] = "img.txt"; // Replace with your file name
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Failed to open file %s\n", filename);
    }

    char art[MAX_HEIGHT][MAX_WIDTH];
    int row = 0;
    int col = 0;
    char c;

    // Read the art from the file into a 2D array
    while ((c = fgetc(file)) != EOF) {
        if (c == '\n') {
            row++;
            col = 0;
        } else {
            art[row][col] = c;
            col++;
        }
    }

    // Print the art to the console
    for (int i = 0; i <= row; i++) {
        for (int j = 0; j < MAX_WIDTH && art[i][j] != '\0'; j++) {
            putchar(art[i][j]);
        }
        putchar('\n');
    }

    fclose(file);
}
