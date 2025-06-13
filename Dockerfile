FROM alpine AS chmodder
ARG TARGETARCH
ARG COMPONENT
COPY /artifacts/server /app/beam-cert-manager
RUN chmod +x /app/*

FROM gcr.io/distroless/cc-debian12
COPY --from=chmodder /app/beam-cert-manager /usr/local/bin/beam-cert-manager
ENTRYPOINT [ "/usr/local/bin/beam-cert-manager" ]