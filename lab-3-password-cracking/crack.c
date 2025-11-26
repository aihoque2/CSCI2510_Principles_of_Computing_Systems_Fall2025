//This program brute-forces a given password hash by trying all possible
//passwords of a given length.
//
//Usage:
//crack <threads> <keysize> <target>
//
//Where <threads> is the number of threads to use, <keysize> is the maximum
//password length to search, and <target> is the target password hash.
//
//For example:
//
//./crack 1 5 na3C5487Wz4zw
//
//Should return the password 'apple'

// crack.c

#include <crypt.h>
#include <unistd.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <pthread.h>
#include <stdbool.h>
#include <string.h>


#define ALPHABET_SIZE 26

char ALPHABET[] = "abcdefghijklmnopqrstuvwxyz"
                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                  "0123456789./";

struct crypt_data* data_arr;

bool stop = false;
pthread_mutex_t stop_mutex = PTHREAD_MUTEX_INITIALIZER;
char found_pass[8]; // buffer to store found password (max key size is 8)
pthread_mutex_t pswd_mutex = PTHREAD_MUTEX_INITIALIZER;


// helper for crack_func() to generate keys
void idx_to_test_str(int idx, char* out, int keysize){
  // keysize: size of password str
  for (int i = keysize - 1; i >= 0; i--){
    out[i] = ALPHABET[idx % ALPHABET_SIZE];
    idx /= ALPHABET_SIZE;
  }
  out[keysize] = '\0';
}

// thread-safe getter for stop
int get_stop(){
    int ret_stop;
    pthread_mutex_lock(&stop_mutex);
    ret_stop = stop;
    pthread_mutex_unlock(&stop_mutex);
    return ret_stop;
}

struct ThreadArg{
  char salt[3];      // 3 bytes salt
  char* expected;    //  expected hash
  int idx;           // the index of the thread
  int start;         // start idx of keys to test (inclusive)
  int end;           // end idx of keys to test (exclusive)
  int keysize;       // given keysize
};


void* crack_func(void* arg)
{

  // get our args
  struct ThreadArg* arg_ptr = (struct ThreadArg*) arg;
  char* salt     = arg_ptr->salt;
  char* expected = arg_ptr->expected;
  int   tidx     = arg_ptr->idx;
  int   start    = arg_ptr->start;
  int   end      = arg_ptr->end;
  int   keysize  = arg_ptr->keysize;

  char* test_str = malloc(keysize + 1); // +1 bc null byte
  if (!test_str) {
    perror("malloc test_str");
    return NULL;
  }

  char* result; // result string after calling crypt()

  for (int i = start; i < end; i++){
    // check global stop flag
    if (get_stop()){
      free(test_str);
      return NULL;
    }

    // generate my keys now
    idx_to_test_str(i, test_str, keysize);
    
    // IMPORTANT: use data_arr[tidx], not data_arr[i]
    result = crypt_r(test_str, salt, &data_arr[tidx]);
    if( result == NULL ){
      perror("crypt_r() failed");
      free(test_str);
      return NULL;
    }

    if (strcmp(result, expected) == 0) {
      // save found password
      pthread_mutex_lock(&pswd_mutex);
      strcpy(found_pass, test_str);
      pthread_mutex_unlock(&pswd_mutex);

      // tell everyone to stop
      pthread_mutex_lock(&stop_mutex);
      stop = true;
      pthread_mutex_unlock(&stop_mutex);

      break;
    }
  }

  free(test_str);
  return NULL;   // don't return &match (that would dangle)
}

int main( int argc, char* argv[] ){

	if( argc != 4 ){
		printf("Usage: %s <threads> <keysize> <target>\n", argv[0]);
		return -1;
	}
  
  // init threads 
	int num_threads = atoi(argv[1]);
	int keysize     = atoi(argv[2]);
	char* target    = argv[3];

  if (num_threads <= 0 || keysize <= 0) {
    fprintf(stderr, "threads and keysize must be > 0\n");
    return -1;
  }

  pthread_t* threads_arr = malloc(num_threads * sizeof(pthread_t));
  if (!threads_arr) {
    perror("malloc threads_arr");
    return -1;
  }

  // central data store for storing crypt_r() results
  data_arr = malloc(num_threads * sizeof(struct crypt_data));
  if (!data_arr) {
    perror("malloc data_arr");
    return -1;
  }
  for (int i = 0; i < num_threads; i++){
    memset(&data_arr[i], 0, sizeof(struct crypt_data));
  }

  // create thread args array
  struct ThreadArg* args = malloc(num_threads * sizeof(struct ThreadArg));
  if (!args) {
    perror("malloc args");
    return -1;
  }
  
  // our expected hash string is the full target (salt + hash)
  char* expected = target;

  // compute salt from target
  char salt[3];
  salt[0] = target[0];
  salt[1] = target[1];
  salt[2] = '\0';



  for (int ksize = 1; ksize <= keysize; ksize++){

    printf("here's ksize: %d\n", ksize);

    int total_keys = 1;
    // calc total keys = ALPHABET_SIZE^keysize
    for (int i = 0; i < keysize; i++){
      total_keys *= ALPHABET_SIZE;
    }

    // divide keyspace among threads
    int base  = total_keys / num_threads;
    int extra = total_keys % num_threads; // number of threads that will analyze extra keys
    int curr  = 0;

    for (int i = 0 ; i < num_threads; i++){
      int chunk = base + (i < extra ? 1 : 0);

      args[i].idx      = i;
      args[i].start    = curr;
      args[i].end      = curr + chunk;
      args[i].keysize  = ksize;
      args[i].expected = expected;

      args[i].salt[0] = salt[0];
      args[i].salt[1] = salt[1];
      args[i].salt[2] = '\0';

      curr += chunk;

      pthread_create(&threads_arr[i], NULL, crack_func, &args[i]);
    }
    // wait for threads
    for (int i = 0 ; i < num_threads; i++){
      pthread_join(threads_arr[i], NULL);
    }
    pthread_mutex_lock(&stop_mutex);
    bool found = stop;
    pthread_mutex_unlock(&stop_mutex);
    if (found) {
      printf("We found the password: %s\n", found_pass);
      break;
    } 

}

  pthread_mutex_lock(&stop_mutex);
  bool found = stop;
  pthread_mutex_unlock(&stop_mutex);
  if (!found) printf("No password found!\n");


  free(threads_arr);
  free(args);
  free(data_arr);

  return 0;
}
