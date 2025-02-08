#!/bin/bash

/app/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 run:app &
nginx -g "daemon off;"

