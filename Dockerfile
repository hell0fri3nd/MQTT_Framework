# syntax=docker/dockerfile:1

FROM python:3

WORKDIR ./

COPY requirements.txt requirements.txt
RUN apt-get install -y libcap2-bin tshark && \
    pip3 install -r requirements.txt

RUN git clone --depth 1 --branch master https://gitlab.com/akihe/radamsa.git && \
    cd radamsa && \
    make -j$(nproc) && \
    make -j$(nproc) install

COPY . .

CMD [ "python3", "./run.py"]
