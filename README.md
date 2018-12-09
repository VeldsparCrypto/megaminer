# compiling
Get the source from github:

```
git clone https://github.com/VeldsparCrypto/megaminer.git
cd megaminer
```

compile the code and produce 'megaminer', linux with gcc installed.
```
gcc -pthread ./src/main.c -o ./megaminer
```

running it:
```
./megaminer --address <your wallet address> --threads 16 --node 127.0.0.1:14242
```
