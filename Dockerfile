ARG BASE_IMAGE=eclipse-temurin:11-jdk

############################
## Container to download
FROM debian:bookworm as curl

ARG GHIDRA_VERSION=10.3.2
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip
ARG GHIDRA_SHA=a658677a87d0be12ab65bd7962f471875b81a2dd2ea35d69cc3201555ca1bd6f

# Download and install Ghidra to /opt
RUN apt update \
    && apt install -y --no-install-recommends curl unzip \
    && curl -L -k -o /tmp/ghidra.zip "${GHIDRA_URL}" \
    && echo "${GHIDRA_SHA} /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q -d /tmp/ /tmp/ghidra.zip \
    && mv "/tmp/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra

############################
## Container to save
FROM $BASE_IMAGE

# install various dependencies for Ghidra
RUN apt update \
    && apt install -y --no-install-recommends \
        fontconfig \
        libxi6 \
        libxrender1 \
        libxtst6

COPY --from=curl /opt/ghidra /opt/ghidra

ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
