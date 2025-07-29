#!/bin/bash

echo "Generating CSS..."
./tailwindcss -i ./static/css/input.css -o ./static/css/output.css --content "./templates/*.html,./static/js/*.js" --minify

echo "Starting app..."
gunicorn --bind 0.0.0.0:5000 app:app --log-level debug