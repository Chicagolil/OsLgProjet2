/**
* @file hangman.c
* @brief a hangman game for 1 player
* @detail uses doubling memory allocation to allow the computer to choose a random word
*
* @author Luke Rindels
* @date April 6, 2017
*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include "hangman.h"

#define LEN 1024 //for character buffers
#define DEF 3 //added to string length of word if user data is out of range
#define NB_GUESSES 8 //default number of guesses


int main()
{
    char buf[LEN];
    char *word;
    char m;
    int guesses;
    srandom(time(NULL));
    struct diction_t *dictionary = file_open();
    
    system("clear");
    printf("\n---------- Welcome to Hangman! ----------\n\n");
    
    // game loop
    while(1) {
        
        system("clear");
        
        puts("");
        
        // computer picks word
        printf("Okay, I will play with you. I have a word in mind.\n");
        word = get_word(dictionary);
        
        // guesses = strlen(word) + 5 - diff;
        int default_number_of_guesses = NB_GUESSES;
        guesses = default_number_of_guesses;
        printf("You get %d guesses.\n", guesses);
        
        make_hangman(word, guesses);
        break;
        
        printf("\nWould you like to play again? [y,n]: ");
        fgets(buf, LEN, stdin);
        sscanf(buf, "%c", &m);
        
        system("clear");
        m = tolower(m);
        
        switch(m) {
            case('y'):
            printf("\nAlright! Let's play again.\n");
            break;
            case('n'):
            free_mem(dictionary);
            printf("\nThat's fine, come back soon!\n");
            return 0;
            default:
            printf("\nThat wasn't one of the options so I'm going to assume you want to play again.\n");
        }
    }
    
    return 0;
}

/*
* Prompts user to enter a guess and stores it in the provided char pointer
*
* @param g the char pointer where the guess will be stored
*/
void enter_guess(char *g)
{
    char buf[LEN];
    printf("\nEnter a letter to guess: ");
    fgets(buf, LEN, stdin);
    sscanf(buf, "%c", g);
    *g = tolower(*g);
}

/**
* Displays the game board to stdout
*
* @param word the word being guessed
* @param guesses the number of tries the player gets
*/
void make_hangman(char *word, int guesses)
{
    int len = strlen(word);
    int used[26] = {0};
    char prog[len];
    char key[len];
    char g;
    int i;
    int n;
    int c;
    
    for (i = 0; i < len; i++) {
        prog[i] = '_';
        key[i] = tolower(word[i]);
    }
    
    while (guesses > 0) {
        n = 0;
        c = 0;
        puts("");
        printf("**************************************\n");
        puts(""); 
        printf("*****************************\\\\|//**\n");
        printf("**You have %d guesses left     \\|/\n", guesses);
        printf("**                             |\n");
        printf("**                            ()\n");
        printf("**                           /||\\\n");
        printf("**                            //\n");
        printf("** ");
        for (i = 0; i < len; i++) {
            printf("%c ", prog[i]);
        }
        printf("\n*************************\n");
        printf("Guessed letters: ");
        for (i = 0; i < 26; i++) { 
            if (used[i] > 0) {
                printf("%c ", 'a' + i);
            } else {
                printf("- ");
            }
        }
        puts("");
        enter_guess(&g);
        
        system("clear");
        
        // verifies letter is in alphabet
        if (!isalpha(g)) {
            printf("\nThat is not a letter of the alphabet.\n");
            continue;
        }
        // verifies letter has not been guessed
        if (used[g - 'a']) {
            printf("\nYou have already guessed the letter %c.\n", g);
            continue;  
        }
        // marks letter as used
        used[g - 'a']++;
        for (i = 0; i < len; i++) {
            if (g == key[i]) {
                prog[i] = g;
                n++; 
            } 
            if (prog[i] != '_') {
                c++;
            }
        }
        // player wins
        if (c == len) {
            printf("\nCongratulations! You guessed the word %s!\n", word);
            return;
        } 
        // wrong guess
        if (n == 0) {
            guesses--;
        }
        // player has guesses left
        if (guesses) {
            printf("\nYou guessed %c and revealed %d characters!\n", g, n);
        } 
        
    }
    printf("\nThe word was %s.\n", word);
    printf("You have no more guesses left. You lose!\n");
}

/**
* Opens and allocates space for the dictionary
* 
* @return the dictionary
*/
struct diction_t *file_open()
{
    int i = 0;
    
    char buf[LEN];
    FILE *fp = fopen("dictionary.txt", "r");
    struct diction_t *dictionary = malloc(sizeof(struct diction_t));
    assert(dictionary);
    
    dictionary->nval = INIT;
    dictionary->max = INIT;
    dictionary->words = NULL;
    /* uses doubling reallocation system */
    while (fgets(buf, LEN, fp)) {
        if (dictionary->words == NULL) {
            dictionary->words = malloc(sizeof(char *));
            assert(dictionary->words);
        } else if (dictionary->nval > dictionary->max) {
            dictionary->words = realloc(dictionary->words, GROW * dictionary->max *sizeof(char *));
            assert(dictionary->words);
            dictionary->max = GROW * dictionary->max;
        }
        dictionary->words[i] = malloc(sizeof(char) * LEN);
        assert(dictionary->words[i]);
        
        strncpy(dictionary->words[i], strtok(buf, "\n"), LEN);
        i++;
        dictionary->nval++;
    }
    dictionary->nval--;
    fclose(fp);
    
    return dictionary;
}

/**
* Frees the memory allocated for the dictionary
*
* @param dictionary the dictionary being freed
*/
void free_mem(struct diction_t *dictionary)
{
    int i;
    
    for (i = 0; i < dictionary->nval; i++) {
        free(dictionary->words[i]);
    }
    free(dictionary->words);
    free(dictionary);
}

/**
* Pulls random word from dictionary
*
* @param dictionary the dictionary being pulled from
* @return a random word
*/
char *get_word(struct diction_t *dictionary)
{
    int r = random() % dictionary->nval;
    return dictionary->words[r];
}