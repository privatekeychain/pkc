FROM ubuntu:18.04

ARG BUILD_JOBS=1

COPY ./sources.list /tmp/sources.list

RUN set -ex; \
    rm /etc/apt/sources.list; cp /tmp/sources.list /etc/apt/sources.list; \
    apt-get update; \
    apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3 libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-test-dev libboost-thread-dev -y; \
    apt-get install libzmq3-dev -y; \
    apt-get install software-properties-common -y; \
    add-apt-repository ppa:bitcoin/bitcoin; \
    apt-get update; \
    apt-get install libdb4.8-dev libdb4.8++-dev -y; \
    apt-get install apache2-utils -y; \
    rm -rf /var/lib/apt/lists/*;

COPY . /tmp/pkc

RUN set -ex; \
    cd /tmp/pkc; \
    ./autogen.sh; \
    ./configure --without-gui --without-miniupnpc; \
    make -j ${BUILD_JOBS}; \
    make install; \
    cd /tmp; \
    rm -rf /tmp/pkc;

# CMD bitcoind

# mainnet: 9332 rpc , 9333 p2p , 8331 zeromq
EXPOSE 9332 9333 8331
