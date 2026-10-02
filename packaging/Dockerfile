# Static SentinelScan image for lab use. The release workflow stages the
# musl binary for each architecture, then builds with:
#   docker buildx build --build-arg BINARY=sentinelscan-amd64 ...
# The binary is fully static, so the runtime image holds nothing else.
FROM scratch
ARG BINARY=sentinelscan
COPY ${BINARY} /sentinelscan
ENTRYPOINT ["/sentinelscan"]
CMD ["--help"]
