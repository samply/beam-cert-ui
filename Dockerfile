FROM alpine AS chmodder
ARG TARGETARCH
ARG COMPONENT
COPY /artifacts /app/beam-cert-manager/
RUN chmod +x /app/beam-cert-manager/server

FROM gcr.io/distroless/cc-debian12
COPY --from=chmodder /app/beam-cert-manager /usr/local/bin/beam-cert-manager
ENTRYPOINT [ "/usr/local/bin/beam-cert-manager/server" ]