FROM golang

# Fetch dependencies
RUN go get github.com/tools/godep

# Add project directory to Docker image.
ADD . /go/src/github.com/immutability-io/reference-app

ENV USER tssbi08
ENV HTTP_ADDR :8888
ENV HTTP_DRAIN_INTERVAL 1s
ENV COOKIE_SECRET jlKAgk0y1PXp0Qe-

# Replace this with actual PostgreSQL DSN.
ENV DSN postgres://tssbi08@localhost:5432/reference-app?sslmode=disable

WORKDIR /go/src/github.com/immutability-io/reference-app

RUN godep go build

EXPOSE 8888
CMD ./reference-app