#!/bin/bash
. .env

(set -ex
  docker build \
    --build-arg KONG_BASE_TAG=${KONG_BASE_TAG} \
    --build-arg LUA_VERSION=${LUA_VERSION} \
    --build-arg LUA_RESTY_OPENIDC_VERSION=${LUA_RESTY_OPENIDC_VERSION} \
    -t ${BUILD_IMG_NAME} \
    -f ${UNIT_PATH}/Dockerfile .
  docker run -it --rm ${BUILD_IMG_NAME} /bin/bash test/unit/run.sh
)

echo "Done"
