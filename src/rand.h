//
//  rand.h
//  megaminer
//
//  Created by Adrian Herridge on 02/12/2018.
//  Copyright © 2018 Veldspar. All rights reserved.
//

#ifndef rand_h
#define rand_h

unsigned long bounded_rand(unsigned long max) {
#ifdef __POSIX_OS__
    unsigned long
    // max <= RAND_MAX < ULONG_MAX, so this is okay.
    num_bins = (unsigned long) max + 1,
    num_rand = (unsigned long) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins;
    
    long x;
    do {
        x = random();
    }
    // This is carefully written not to overflow
    while (num_rand - defect <= (unsigned long)x);
    
    // Truncated division is intentional
    return x/bin_size;
#else
    // shitty windows can't do anything right
    unsigned int    number;
    errno_t         err;
    err = rand_s(&number);
    if (err != 0)
    {
        printf("The rand_s function failed!\n");
        exit(0);
    }
    return  (unsigned long long)(((double)number / ((double)UINT_MAX + 1) * max) + 1);
#endif // __POSIX_OS__
    
}

#endif /* rand_h */
