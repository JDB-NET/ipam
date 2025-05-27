#!/bin/bash

echo "Generating CSS..."
./tailwindcss -i ./static/css/input.css -o ./static/css/output.css --content "./templates/*.html,./static/js/*.js" --minify

echo "Starting app..."
python app.py