FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install -y curl dnsutils jq libxml2-utils whois
WORKDIR /app
COPY src/behindTheCDN.sh /app
RUN chmod +x ./behindTheCDN.sh
CMD ["./behindTheCDN.sh"]
