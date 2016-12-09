#!/bin/bash
cd ./gateserver
python2.7 ./gateserver.py &
cd ../lobbyserver
python2.7 lobbyserver.py &