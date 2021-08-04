# syntax=docker/dockerfile:1

FROM python:3

# set environment as non interactive to avoid tshark's prompts
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR ./

# copy requirements.txt
COPY requirements.txt requirements.txt

# install tshark
RUN apt-get update -y && apt-get install tshark -y

# install nmap and requirements libraries
RUN apt-get install nmap -y && \
    pip3 install -r requirements.txt

# compile radamsa
RUN git clone --depth 1 --branch master https://gitlab.com/akihe/radamsa.git && \
    cd radamsa && \
    make -j$(nproc) && \
    make -j$(nproc) install

COPY . .

CMD [ "python3", "./run.py"]
