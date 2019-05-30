FROM ubuntu:18.04

ARG BUILD_JOBS=1

COPY ./sources.list /tmp/sources.list

RUN set -ex; \
    rm /etc/apt/sources.list; cp /tmp/sources.list /etc/apt/sources.list; \
    apt-get update; \
    apt-get install apache2-utils wget -y; \
# dependies of bitcoin
    apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils python3 libboost-system-dev libboost-filesystem-dev libboost-chrono-dev libboost-test-dev libboost-thread-dev -y; \
    apt-get install libzmq3-dev -y; \
    apt-get install software-properties-common -y; \
    add-apt-repository ppa:bitcoin/bitcoin; \
    apt-get update; \
    apt-get install libdb4.8-dev libdb4.8++-dev -y; \
# dependies of btcpool
    apt-get install build-essential autotools-dev libtool autoconf automake pkg-config cmake \
                   openssl libssl-dev libcurl4-openssl-dev libconfig++-dev \
                   libboost-all-dev libgmp-dev libmysqlclient-dev libzookeeper-mt-dev \
                   libzmq3-dev libgoogle-glog-dev libhiredis-dev zlib1g zlib1g-dev \
                   libprotobuf-dev protobuf-compiler -y; \
    rm -rf /var/lib/apt/lists/*;

# btcpool 依赖的指定版本的libevent
RUN set -ex; \
    cd /tmp; \
    wget https://github.com/libevent/libevent/releases/download/release-2.1.9-beta/libevent-2.1.9-beta.tar.gz; \
    tar zxf libevent-2.1.9-beta.tar.gz; \
    cd libevent-2.1.9-beta; \
    ./autogen.sh; \
    ./configure --disable-shared; \
    make -j${BUILD_JOBS}; \
    make install; \
    rm -rf /tmp/*;

# btcpool 依赖的指定版本的librdkafka 
RUN set -ex; \
    cd /tmp; \
    wget https://github.com/edenhill/librdkafka/archive/0.9.1.tar.gz; \
    tar zxf 0.9.1.tar.gz; \
    cd librdkafka-0.9.1; \
    ./configure; \
    make -j${BUILD_JOBS}; \
    make install; \
    rm -rf /tmp/*; \
    cd /usr/local/lib; \
    find . | grep 'rdkafka' | grep '.so' | xargs rm;

COPY . /env/pkc

RUN set -ex; \
    cd /env/pkc; \
    ./autogen.sh; \
    ./configure --without-gui --without-miniupnpc; \
    make -j ${BUILD_JOBS}; \
    make install; \
    make clean;
    # cd /env; \
    # rm -rf /env/pkc;

# 源码保留,矿池源码链接
# CMD bitcoind

# mainnet: 9332 rpc , 9333 p2p , 8331 zeromq
EXPOSE 9332 9333 8331
