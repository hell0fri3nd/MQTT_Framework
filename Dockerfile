# syntax=docker/dockerfile:1

FROM python:3.8-slim-buster

WORKDIR ./

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

RUN git clone --depth 1 --branch master https://gitlab.com/akihe/radamsa.git && \
    cd radamsa && \
    make -j$(nproc) && \
    make -j$(nproc) install

COPY . .

CMD [ "python3", "./run.py"]