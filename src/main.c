//
//  main.c
//  megaminer
//
//  Created by Adrian Herridge on 08/08/2018.
//  Copyright © 2018 Veldspar. All rights reserved.
//

// copy of apple's rng.  Very effective and quick

#include "sha512.h"
#include "http.h"
#include "rand.h"
#include <stdio.h>
#include <time.h>
#ifdef __POSIX_OS__
#include <pthread.h>
#include <unistd.h>
#endif

// define the algo specs
int version = 1;
int oreSize = 1024*1024;
const unsigned char oreSeed[56] = { 48,102,99,98,98,56,57,53,49,102,100,48,53,50,55,54,52,102,55,49,97,54,51,52,98,48,50,51,54,49,52,52,56,51,56,54,99,53,98,48,102,55,48,101,97,100,98,55,49,54,99,99,48,102,51,102};
unsigned char magicChar = 255;
int requiredDepth = 2;
int distributionSize = 21;
int distribution[21] = {1,1,1,2,2,2,5,5,5,10,10,20,20,50,50,100,200,500,1000,2000,5000};
int beanBytes = 2;
int segmentsCount = 3;
int hashSearchLength = 28;
float miningLimit = 0.0;
float totalMined = 0.0;
float aveValue = 0.0;
float ticks = 0.0;

char* nodeAddress = NULL;

// define the ore
void* ore = NULL;

const char* address = NULL;
static unsigned int hashesSec = 0;

#ifdef __POSIX_OS__
#include <pthread.h>

/* This is the critical section object (statically allocated). */
static pthread_mutex_t stats_mutex;

#else
// windows land
CRITICAL_SECTION stats_mutex;

#endif



#ifdef __POSIX_OS__
void* miningThread(void *x_void_ptr) {
#else
DWORD WINAPI miningThread(LPVOID lpParam) {
#endif
    
    // where ore is a 1mb selection of random data (static char ore[] = {1,2,3,4 ... etc } )
    // once a basic hash condition is met, we look for beans within the hash from the random selection made form the ore.
    const int oreSize = 1 * (1024 * 1024);
    const int maxRange = oreSize - 64;
    const int selectionSize = segmentsCount*64;
    
    char* immutableOre = malloc(oreSize);
    memcpy(immutableOre, ore, oreSize);
    int iterations = 0;
    
    // so the miner basically has to loop constantly, hashing random points in the ore.
    while (1) {
        
        iterations++;
        if (iterations == 100) {
            iterations = 0;
#ifdef __POSIX_OS__
            pthread_mutex_lock( &stats_mutex );
            hashesSec += 100;
            pthread_mutex_unlock( &stats_mutex );
#else
            EnterCriticalSection(&stats_mutex);
            hashesSec += 100;
            LeaveCriticalSection(&stats_mutex);
#endif
        }
        
        uint32_t segments[segmentsCount];

        // fetch 8 random 64 byte segments from within the ore
        uint8_t *selection = malloc(selectionSize);
        memset(selection, 0, selectionSize);
        
        for (int i = 0; i < segmentsCount; i++) {
            segments[i] = (uint32_t)bounded_rand(maxRange);
            memcpy(selection + (i*64), ((char*)immutableOre) + segments[i], 64);
        }
        
        // now hash it to see if we start within range
        uint8_t *hash = malloc(SHA512_DIGEST_LENGTH);
        memset(hash, 0, SHA512_DIGEST_LENGTH);
        SHA512(selection, selectionSize, hash);
        
        int currentDepth = 0;
        int currentValue = 0;
        while (currentDepth < requiredDepth) {
            
            currentValue = 0;
            
            if(hash[0] == magicChar) {
                
                currentValue = 0;
                
                void* beanSource = malloc(SHA512_DIGEST_LENGTH*5);
                
                // now hash the hash
                uint8_t *beanHash = malloc(SHA512_DIGEST_LENGTH);
                memset(beanHash, 0, SHA512_DIGEST_LENGTH);
                SHA512(hash, SHA512_DIGEST_LENGTH, beanHash);
                memcpy(beanSource, beanHash, SHA512_DIGEST_LENGTH);
                
                for (int i=1; i<5; i++) {
                    
                    memset(beanHash, 0, SHA512_DIGEST_LENGTH);
                    SHA512(beanSource, SHA512_DIGEST_LENGTH*i, beanHash);
                    memcpy(beanSource+(SHA512_DIGEST_LENGTH*i), beanHash, SHA512_DIGEST_LENGTH);
                    
                }
                
                free(beanHash);
                free(beanSource);
                
                void* beans = malloc(distributionSize*beanBytes);
                memset(beans, 0, distributionSize*beanBytes);
                int ptr = SHA512_DIGEST_LENGTH*5;
                for (int i=1; i<=distributionSize; i++) {
                    memcpy(beans+((i-1)*beanBytes), beanSource + (ptr - (beanBytes*i)), beanBytes);
                }
                
                // now loop through, attempting to find a valid bean within this round
                void* beanFound = NULL;
                for (int i=0; i<distributionSize; i++) {
                    void* bean = malloc(beanBytes);
                    memcpy(bean, beans+(i*beanBytes), beanBytes);
                    // now look through to see if this bean is in the hash
                    for (int ptr=0; ptr < hashSearchLength; ptr++) {
                        if(memcmp(bean, hash+ptr, beanBytes) == 0) {
                            beanFound = malloc(beanBytes);
                            memcpy(beanFound, bean, beanBytes);
                            if (currentValue == 0) {
                                currentValue = distribution[i];
                                break;
                            }
                        }
                    }
                    free(bean);
                }
                
                free(beans);
                
                if (beanFound != NULL) {
                    
                    currentDepth++;
                    memcpy(hash, beanFound, beanBytes);
                    free(beanFound);
                    
                    uint8_t *newHash = malloc(SHA512_DIGEST_LENGTH);
                    memset(newHash, 0, SHA512_DIGEST_LENGTH);
                    SHA512(hash, SHA512_DIGEST_LENGTH, newHash);
                    memcpy(hash, newHash, SHA512_DIGEST_LENGTH);
                    
                    free(newHash);
                    
                } else {
                    break;
                }
 
            } else if (currentDepth == requiredDepth) {
                break;
            } else {
                break;
            }
            
            if (currentDepth == requiredDepth) {
                break;
            }
            
        }
        
        if (currentDepth == requiredDepth && currentValue != 0) {
            
            aveValue += (float)currentValue;
            ticks += 1.0;
            printf("average token value = %f\n", ((aveValue / ticks) / 100));
            
            // we have a find, throw it out to the server for registration
            char token[96];
            sprintf(token,"%08X-%04X-%08X-%08X%08X%08X", 0, 0, currentValue, segments[0], segments[1], segments[2]);
            
            time_t timer;
            char buffer[26];
            struct tm* tm_info;
            
            time(&timer);
            tm_info = localtime(&timer);
            
            strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
            puts(buffer);
            
            printf("[%s] Found token: " "\033[0;35m" "%s" "\033[0m" "\n", buffer, token);
            printf("[%s] Value: " "\033[0;33m" "%f" "\033[0m" "\n", buffer, (((float)currentValue) / 100.0f));
            
            // download the ore seed and generate the ore
            char registration[1024];
            memset(&registration, 0, 1024);
            sprintf(registration, "http://%s/register?address=%s&token=%s", nodeAddress, address, token);
            struct http_response* send = http_get(registration, NULL);
            if (send == NULL) {
                printf("Unable to send token registration to network.  Network may currently be offline.\n");
            } else {
                printf("Token sent to the network for registration.\n");
                if (miningLimit) {
                    totalMined += (((float)currentValue) / 100.0f);
                }
                
            }
            
            if (miningLimit) {
                if (totalMined >= miningLimit) {
                    exit(0);
                }
            }
            
        }

        free(selection);
        free(hash);
        
    }
    
}

// http://www.concentric.net/~Ttwang/tech/inthash.htm
unsigned long mix(unsigned long a, unsigned long b, unsigned long c)
{
    a=a-b;  a=a-c;  a=a^(c >> 13);
    b=b-c;  b=b-a;  b=b^(a << 8);
    c=c-a;  c=c-b;  c=c^(b >> 13);
    a=a-b;  a=a-c;  a=a^(c >> 12);
    b=b-c;  b=b-a;  b=b^(a << 16);
    c=c-a;  c=c-b;  c=c^(b >> 5);
    a=a-b;  a=a-c;  a=a^(c >> 3);
    b=b-c;  b=b-a;  b=b^(a << 10);
    c=c-a;  c=c-b;  c=c^(b >> 15);
    return c;
}
    
// seed for PRNG
unsigned long long rdtsc(){
#ifdef __arm__
    return (unsigned long long)(time(NULL) & 0xFFFF) | (getpid() << 16);
#else
#ifdef __POSIX_OS__
    return mix(clock(), time(NULL), getpid());
#else
	// win64 implementation 
	return (unsigned long long)GetTickCount();
#endif
#endif
}

int main(int argc, const char * argv[]) {
    
    // insert code here...
    printf("                                _\n");
    printf("  /\\/\\   ___  __ _  __ _  /\\/\\ (_)_ __   ___ _ __\n");
    printf(" /    \\ / _ \\/ _` |/ _` |/    \\| | '_ \\ / _ \\ '__|\n");
    printf("/ /\\/\\ \\  __/ (_| | (_| / /\\/\\ \\ | | | |  __/ |\n");
    printf("\\/    \\/\\___|\\__, |\\__,_\\/    \\/_|_| |_|\\___|_|\n");
    printf("              |___/                         v0.2.0\n");
    printf("\n");
    printf("          Dogs Dinner Edition\n");
    printf("--------------------------------------------------\n");
    printf("\n");
    
    int threadCount = 4;
    nodeAddress = "127.0.0.1:14242";
    
    if (argc) {
        for (int idx=0; idx < argc; idx++) {
            if (strcmp(argv[idx], "--help") == 0) {
                printf("Commands\n");
                printf("--------\n");
                printf("--address       : Veldspar wallet address, looks like 'VE4DuSf92FRLE26qDXC2y1tyPdmKbk5XcbRg6VXGghxQAi'\n");
                printf("--threads       : Number of threads to abuse\n\n");
                printf("--node          : The address of the node, e.g. public.veldspar.co:14242\n\n");
                exit(0);
            }
            if (strcmp(argv[idx], "--threads") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    threadCount = atoi(argv[idx+1]);
                }
            }
            if (strcmp(argv[idx], "--limit") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    miningLimit = atof(argv[idx+1]);
                }
            }
            if (strcmp(argv[idx], "--node") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    nodeAddress = argv[idx+1];
                }
            }
            if (strcmp(argv[idx], "--address") == 0) {
                // now grab the parameter for threads if the argc is high enough
                if (idx+1 <= argc) {
                    address = argv[idx+1];
                    
                    // I guess we should check the users haven't done something stupid!
                    if (address[0] != 'V' || address[1] != 'E') {
                        printf("Incorrect address specified.\n");
                        exit(0);
                    }
                    
                    if (strlen(address) != 46) {
                        printf("Incorrect address specified.\n");
                        exit(0);
                    }
                    
                }
            }
        }
    }
    
    if (address == NULL) {
        printf("No address specified.");
        exit(0);
    }
    
    printf("Setting up random seed\n");
    uint32_t s = (uint32_t)rdtsc();
    srand(s);
    
    printf("Generating ore\n");
    int size = 0;
    
    ore = malloc(oreSize + SHA512_DIGEST_LENGTH);
    void* newHash = malloc(SHA512_DIGEST_LENGTH);
    SHA512((const uint8_t*)oreSeed, sizeof(oreSeed), newHash);
    memcpy(ore + size, newHash, SHA512_DIGEST_LENGTH);
    size += SHA512_DIGEST_LENGTH;
    free(newHash);
    
    while (size < oreSize) {
        // hash the last hash and append the ore
        
        void* oldHash = malloc(SHA512_DIGEST_LENGTH);
        void* newHash = malloc(SHA512_DIGEST_LENGTH);
        memcpy(oldHash, ore + (size - SHA512_DIGEST_LENGTH), SHA512_DIGEST_LENGTH);
        SHA512(oldHash, SHA512_DIGEST_LENGTH, newHash);
        memcpy(ore + size, newHash, SHA512_DIGEST_LENGTH);
        size += SHA512_DIGEST_LENGTH;
        free(oldHash);
        free(newHash);
        
    }
    
#ifdef __POSIX_OS__
    pthread_t threads[threadCount];
    pthread_mutex_init(&stats_mutex, NULL);
#else
    InitializeCriticalSection(&stats_mutex);
	DWORD threadIDs[1024];
	HANDLE threads[1024];
#endif
    for (int i=0; i < threadCount; i++) {
        printf("Starting mining thread %i\n", i);
#ifdef __POSIX_OS__
        pthread_create(&threads[i], NULL, miningThread, NULL);
#else
		threads[i] = CreateThread(NULL, 0, miningThread, NULL, 0, &threadIDs[i]);
#endif
    }
    
    while(1) {
        //dirty, but it's 11pm.
#ifdef __POSIX_OS__
        sleep(1);
#else
		Sleep(1000);
#endif
        
        // now report the stats because people love to see numbers!
        unsigned int rate = 0;
#ifdef __POSIX_OS__
        pthread_mutex_lock( &stats_mutex );
        rate = hashesSec;
        hashesSec = 0;
        pthread_mutex_unlock( &stats_mutex );
#else
        EnterCriticalSection(&stats_mutex);
        rate = hashesSec;
        hashesSec = 0;
        LeaveCriticalSection(&stats_mutex);
#endif
        
        if (rate < 1000) {
            // h/s
            printf("Hash rate: %u h/s\n", rate);
        } else if (rate < 1000000) {
            // kh/s
            printf("Hash rate: %f Kh/s\n", ((double)rate / 1000.0));
        } else {
            // mh/s
            printf("Hash rate: %f Mh/s\n", ((double)rate / 1000000.0));
        }
        
    }
    
    return 0;
}

