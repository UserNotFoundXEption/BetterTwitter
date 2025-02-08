FROM ubuntu:latest
RUN apt-get update -qq && apt-get install -y -qq \
	vim python3 python3-pip python3-venv nginx\
	build-essential gunicorn --no-install-recommends > /dev/null 2>&1
	
WORKDIR /app
COPY ./backend .
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./certs /etc/nginx/certs

ENV APP_SECRET="t6x/HgAZeUUJDBJtwbfnYLDOetC4lNqxkgJHN0DWZC0="
ENV SALT_SECRET="C5582LPWwonCD27qpw4Tnz1OoeP4ptLaWB50RldNvso="
ENV KEY_SECRET="7TAVi+Lxcs+nnNioRqADoaNYVzLMIyVRKIfJ4Fu7ng0="
ENV TOTP_SECRET="DAUXOZ0VzhmDSmTXhQQoNS5DnmYJZls1m7ihA504KjI="

RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt -q > /dev/null 2>&1

EXPOSE 443

COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]

