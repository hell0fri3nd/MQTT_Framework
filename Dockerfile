# syntax=docker/dockerfile:1

FROM python:3

WORKDIR ./

# copy requirements.txt
COPY requirements.txt requirements.txt

# install tshark without user interaction
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

# install nmap and requirements libraries
RUN apt-get install nmap && \
    pip3 install -r requirements.txt

# compile radamsa
RUN git clone --depth 1 --branch master https://gitlab.com/akihe/radamsa.git && \
    cd radamsa && \
    make -j$(nproc) && \
    make -j$(nproc) install

COPY . .

CMD [ "python3", "./run.py"]
