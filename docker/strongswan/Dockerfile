FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    strongswan \
    strongswan-pki \
    libcharon-extra-plugins \
    libstrongswan-extra-plugins \
    iproute2 \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["ipsec", "start", "--nofork"]