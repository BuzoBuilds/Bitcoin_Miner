#!/bin/bash
/usr/bin/g++ -fdiagnostics-color=always -g /home/amby/projects/bitcoin_miner_2/src/*.cpp -o /home/amby/projects/bitcoin_miner_2/src/../bin/main -pthread -L/home/amby/projects/bitcoin_miner_2/src/crypto++_lib -lcryptopp
