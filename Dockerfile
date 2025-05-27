FROM python:3.13-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y sqlite3 curl
RUN rm -rf /var/lib/apt/lists/*
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && mv tailwindcss-linux-x64 tailwindcss \
    && ./tailwindcss -i ./static/css/input.css -o ./static/css/output.css --content "./templates/*.html,./static/js/*.js" --minify
EXPOSE 5000
CMD ["python", "app.py"]
