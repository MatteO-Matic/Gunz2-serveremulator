#!/bin/bash
cd ./gateserver
terminix -a session-add-right -x "python2.7 ./gateserver.py"
cd ../lobbyserver
clear
python2.7 lobbyserver.py