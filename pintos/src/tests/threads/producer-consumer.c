/* Tests producer/consumer communication with different numbers of threads.
 * Automatic checks only catch severe problems like crashes.
 */

#include <stdio.h>
#include <string.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"


void producer_consumer(unsigned int num_producer, unsigned int num_consumer);
void put(char p_letter,char* producer_name);
void get(char* consumer_name);
void producer(void *);
void consumer(void *);
char *word = "Hello world";
char buffer[15];
struct condition empty;
struct condition fill;
struct lock mutex;
int give;
int use;
int count;


void test_producer_consumer(void)
{
    /*producer_consumer(0, 0);
    producer_consumer(1, 0);
    producer_consumer(0, 1);
    producer_consumer(1, 1);
    producer_consumer(3, 1);
    producer_consumer(1, 3);
    producer_consumer(4, 4);
    producer_consumer(7, 2);
    producer_consumer(2, 7);*/
    producer_consumer(6, 6);
    pass();
}


void producer_consumer(UNUSED unsigned int num_producer, UNUSED unsigned int num_consumer)
{
     /* FIXME implement */

     /* initialising the conditional variables and lock*/
cond_init(&empty);
cond_init(&fill);
lock_init(&mutex);


/* defining other necessary variables*/
   give = 0;
   use = 0;
   count = 0;

/*spawning threads according the the given numbers*/
   for (unsigned int i = 0; i < num_producer; i++) {
       char producer_name[15];
       snprintf(producer_name, sizeof producer_name, "producer-%d", i);
       thread_create(producer_name, 0, producer, NULL);
   }

   for (unsigned int j = 0; j < num_consumer; j++) {
       char consumer_name[15];
       snprintf(consumer_name, sizeof consumer_name, "consumer-%d", j);
       thread_create(consumer_name, 0, consumer, NULL);
   }

   return;

}
   
/*adding the character into the buffer which the producers call*/
void put(char t_letter, char* producer_name) {
    buffer[give] = t_letter;
    give = give + 1 ;
    count++;
    printf ("%s gave %c\n", producer_name, t_letter);
    return;
}

/*taking the character from the buffer which the consumers call*/
void get(char* consumer_name) {
    char tmp = buffer[use];
    use = use + 1;
    count--;
    printf ("%s used %c\n", consumer_name, tmp);
    return;
}

/*the producer function*/
void producer(void *arg) {
    int string_length = strlen(word);
    while (true) {
        lock_acquire(&mutex);
        if (give < string_length) {            /*checking if the string has been completely added or not*/
        while(count == string_length) {        /*checking if the buffer has space*/
            printf("Buffer is full");
            cond_wait(&empty, &mutex);   
        } 
    put(word[give], thread_name());
    cond_signal(&fill, &mutex);
    lock_release(&mutex);
        }
        else {
            lock_release(&mutex);
            thread_exit();
        }
    
}
}

void consumer(void *arg) {
    int string_length = strlen(word);
    while(true) {
        lock_acquire(&mutex);
         if (use < string_length) {            /*checking if the string has been completely printed or not*/
        while(count == 0) {                    /*checking if the buffer is empty*/
            printf("Buffer is empty");
            cond_wait(&fill, &mutex);
            
        } 
    get(thread_name());
    cond_signal(&empty, &mutex);
    lock_release(&mutex);
        }
        else {
            lock_release(&mutex);
            thread_exit();
        }
    }
}