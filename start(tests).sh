#!/bin/bash

/app/venv/bin/python3 run.py &
nginx -g "daemon off;"

