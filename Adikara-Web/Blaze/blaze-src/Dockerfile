FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y libc6 libstdc++6 software-properties-common && \
    add-apt-repository ppa:dotnet/backports && \
    apt-get install -y dotnet6

WORKDIR /app

COPY ./src /app

COPY ./flag.txt /flag.txt

RUN chmod +x /app/BlazeBleed

EXPOSE 5000

ENTRYPOINT ["/app/BlazeBleed"]

