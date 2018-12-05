//
//  rand.h
//  megaminer
//
//  Created by Adrian Herridge on 02/12/2018.
//  Copyright © 2018 Veldspar. All rights reserved.
//

#ifndef rand_h
#define rand_h

uint32_t bounded_rand(uint32_t max) {
#ifdef __POSIX_OS__
    uint32_t r = rand() % max;
    return r;
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
