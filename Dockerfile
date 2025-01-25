FROM ubuntu:latest
RUN apt-get update && apt-get install -y \
	vim python3 python3-pip python3-venv \
	build-essential --no-install-recommends
WORKDIR /app
COPY ./backend .

RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["/app/venv/bin/python3", "run.py"]

