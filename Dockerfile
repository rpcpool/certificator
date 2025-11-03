FROM alpine:latest

WORKDIR /app

COPY certificator certificatee /app/

CMD [ "/app/certificator" ]
