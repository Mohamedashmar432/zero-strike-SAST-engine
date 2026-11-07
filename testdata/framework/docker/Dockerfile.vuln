FROM ubuntu:latest AS build
RUN apt-get update

FROM node
ENV DB_PASSWORD=synthetic-pass-1234 NODE_ENV=production
ARG API_TOKEN=synthetic-token-abcd
ADD https://example.test/tool.tar.gz /opt/
CMD ["node", "app.js"]
