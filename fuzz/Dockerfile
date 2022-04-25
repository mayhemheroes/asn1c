# Build Stage
FROM --platform=linux/amd64 ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake gcc build-essential autoconf libtool

## Add source code to the build stage.
ADD . /src
WORKDIR /src

RUN test -f configure || autoreconf -iv
RUN ./configure
RUN make
RUN make install

# Package Stage
FROM --platform=linux/amd64 ubuntu:20.04

RUN mkdir /corpus

COPY --from=builder /src/asn1c/asn1c /
COPY --from=builder /src/tests/tests-asn1c-compiler/*.asn1 /corpus/
