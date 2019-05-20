FROM ubuntu:18.04

ARG BUILD_JOBS=1

COPY ./sources.list /tmp/sources.list

RUN set -ex; \
    rm /etc/apt/sources.list; cp /tmp/sources.list /etc/apt/sources.list; \
    apt-get update; \
    apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3 libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-test-dev libboost-thread-dev -y; \
    apt-get install libzmq3-dev -y; \
    apt-get install apache2-utils -y; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /tmp/pkc;

COPY ./latest.tar.gz /tmp/pkc

RUN set -ex; \
    cd /tmp/pkc; \
    tar -xvzf latest.tar.gz; \
    rm -rf latest.tar.gz; \
    ./autogen.sh; \
    ./configure --disable-wallet --without-gui --without-miniupnpc; \
    make -j ${BUILD_JOBS}; \
    make install; \
    cd /tmp; \
    rm -rf /tmp/pkc;

# CMD bitcoind

# mainnet: 9332 rpc , 9333 p2p , 8331 zeromq
EXPOSE 9332 9333 8331
