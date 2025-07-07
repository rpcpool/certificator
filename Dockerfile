FROM alpine:latest

WORKDIR /app

COPY certificator /app/certificator

CMD [ "/app/certificator" ]
