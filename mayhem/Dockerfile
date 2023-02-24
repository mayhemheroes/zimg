FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake pkg-config libtool clang

COPY . /repo
WORKDIR /repo
RUN ./autogen.sh
RUN ./configure --enable-testapp
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_parse_document.cpp -fsanitize=fuzzer,address -o /fuzz -I /repo/src/testcommon /repo/src/testcommon/json.cpp

FROM ubuntu:22.04 as package
COPY --from=builder /repo/testapp /
COPY --from=builder /fuzz /fuzz_parse_document
