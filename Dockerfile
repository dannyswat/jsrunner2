# syntax=docker/dockerfile:1

FROM golang:1.21-alpine as base

# Set destination for COPY
WORKDIR /gobuild

# Download Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY config/*.go ./config/
COPY handlers/*.go ./handlers/
COPY middlewares/*.go ./middlewares/
COPY security/*.go ./security/
COPY utils/*.go ./utils/
COPY main.go ./
COPY *.html  ./
COPY static/ ./static/
# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /jsrunner-server

FROM centos:8

COPY --from=base /jsrunner-server /jsrunner-server
COPY --from=base /gobuild/*.html /
COPY --from=base /gobuild/static/ /static/

# Optional:
# To bind to a TCP port, runtime parameters must be supplied to the docker command.
# But we can document in the Dockerfile what ports
# the application is going to listen on by default.
# https://docs.docker.com/reference/dockerfile/#expose
EXPOSE 8080

# Run
CMD ["/jsrunner-server"]