FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y install \
        make gcc g++
