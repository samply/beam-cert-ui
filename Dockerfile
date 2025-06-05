FROM alpine AS chmodder
ARG TARGETARCH
ARG COMPONENT
COPY /artifacts/server /app/beam-cert-ui
RUN chmod +x /app/*

FROM gcr.io/distroless/cc-debian12
COPY --from=chmodder /app/beam-cert-ui /usr/local/bin/beam-cert-ui
ENTRYPOINT [ "/usr/local/bin/beam-cert-ui" ]