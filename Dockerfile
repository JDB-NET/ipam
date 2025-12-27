FROM python:3.13-slim
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y curl mariadb-client-compat
RUN rm -rf /var/lib/apt/lists/*
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64 \
    && chmod +x tailwindcss-linux-x64 \
    && ./tailwindcss-linux-x64 -i ./static/css/input.css -o ./static/css/output.css --content "./templates/*.html,./static/js/*.min.js" --minify \
    && rm tailwindcss-linux-x64
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--log-level", "warning"]