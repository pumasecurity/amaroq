ARG VERSION="0.0"

# build stage
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build

# copy source files
WORKDIR /build
COPY ./sarif-sdk/ ./

# restore and build binary
RUN dotnet restore ./src/Sarif.Multitool/Sarif.Multitool.csproj
RUN dotnet publish ./src/Sarif.Multitool/Sarif.Multitool.csproj --configuration Release --framework netcoreapp3.1 --runtime linux-musl-x64 -p:PublishTrimmed=True --output ./bin

# runtime stage
FROM mcr.microsoft.com/dotnet/runtime-deps:6.0.8-alpine3.16
LABEL maintainer="support@pumasecurity.io"

# env vars
ARG VERSION
ENV AMAROQ_VERSION=${VERSION}

# install packages
RUN apk add --no-cache \
    jq=1.6-r1 bash=5.1.16-r2 coreutils=9.1-r0 \
    python3=3.10.5-r0 py3-pip=22.1.1-r0

# set shared bundle extract directory
ARG DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/tmp/
ENV DOTNET_BUNDLE_EXTRACT_BASE_DIR=${DOTNET_BUNDLE_EXTRACT_BASE_DIR}

# copy sarif tooling
COPY --from=build /build/bin/Sarif.Multitool /usr/local/bin/sarif

# install amaroq pip package
ARG AMAROQ_PATH=/opt/share/amaroq
RUN mkdir -p ${AMAROQ_PATH}
COPY ./src/ ${AMAROQ_PATH}/
RUN pip3 install ${AMAROQ_PATH}

ENTRYPOINT []
