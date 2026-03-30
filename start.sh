#!/bin/bash

echo "Starting DarkWeb Monitor..."

gunicorn app:app --bind 0.0.0.0:$PORT
