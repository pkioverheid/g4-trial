#!/bin/bash

cwd=$(pwd)
cd "$cwd"/ca && python3 -m http.server 8080