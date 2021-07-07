#syntax=docker/dockerfile:1.2

# Base with APT packages installed
FROM registree/teaclave-build:latest AS builder

ENV SGX_SDK=/opt/sgxsdk

WORKDIR /root/rtc-data
ARG SGX_MODE=HW

# TODO only copy what we need
COPY . .

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    . /root/.cargo/env && cargo fetch

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,sharing=private,target=/root/rtc-data/target \
    --mount=type=cache,sharing=private,target=/root/rtc-data/rtc_data_enclave/target \
    ./runbuild.sh && \
    mkdir /root/out && \
    cp target/release/http_server /root/out/http_server

FROM registree/teaclave-build:latest AS runsw

WORKDIR /root/rtc-data
COPY --from=builder /root/rtc-data/rtc_data_service/http_server/config ./config
COPY --from=builder /root/out/http_server ./http_server
COPY --from=builder /root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so ./data_enclave.signed.so
COPY --from=builder /root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so ./auth_enclave.signed.so
COPY --from=builder /root/rtc-data/rtc_exec_enclave/build/bin/enclave.signed.so ./exec_enclave.signed.so

EXPOSE 8080

CMD ["./http_server"]

FROM registree/sgx-run:latest AS runhw

WORKDIR /root/rtc-data

COPY --from=builder /root/rtc-data/rtc_data_service/http_server/config ./config
COPY --from=builder /root/out/http_server ./http_server
COPY --from=builder /root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so ./data_enclave.signed.so
COPY --from=builder /root/rtc-data/rtc_auth_enclave/build/bin/enclave.signed.so ./auth_enclave.signed.so
COPY --from=builder /root/rtc-data/rtc_exec_enclave/build/bin/enclave.signed.so ./exec_enclave.signed.so

EXPOSE 8080

CMD ["./http_server"]
