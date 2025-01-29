FROM ubuntu:latest
RUN apt-get update -qq && apt-get install -y -qq \
	vim python3 python3-pip python3-venv nginx\
	build-essential gunicorn --no-install-recommends > /dev/null 2>&1
	
WORKDIR /app
COPY ./backend .
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./certs /etc/nginx/certs

RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt -q > /dev/null 2>&1

EXPOSE 443

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

