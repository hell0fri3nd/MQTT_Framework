# syntax=docker/dockerfile:1

FROM python:3

# set environment as non interactive to avoid tshark's prompts
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR ./

# copy requirements.txt
COPY requirements.txt requirements.txt

# install tshark
RUN apt-get update -y && \
    apt-get install tshark -y

# install nmap
RUN apt-get update -y && \
    apt-get install nmap -y

# install less
RUN apt-get update -y && \
    apt-get install less

# install prettytable
RUN pip install -U prettytable

# install requirements libraries
RUN pip3 install -r requirements.txt

# compile radamsa from source
RUN git clone --depth 1 --branch master https://gitlab.com/akihe/radamsa.git && \
    cd radamsa && \
    make -j$(nproc) && \
    make -j$(nproc) install

COPY . .

CMD [ "python3", "./run.py"]
