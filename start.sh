#!/bin/bash

echo "Starting DarkWeb Monitor..."

cd darkweb_monitor

gunicorn app:app --bind 0.0.0.0:$PORT
