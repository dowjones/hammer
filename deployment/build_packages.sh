#!/usr/bin/env bash

set -e

usage() {
    >&2 echo "Usage: $(basename $0) <path_to_config_file>"
}

if [ "$#" -lt 1 ]; then
    usage
    exit 1
fi

CONFIG_FILE="$( cd "$(dirname "$1")" ; pwd -P )"/$(basename "$1")
if [ ! -e "${CONFIG_FILE}" ]; then
    >&2 echo "Provided configuration file '$1' does not exist"
    usage
    exit 1
fi
CONFIG_DIR="$(dirname "${CONFIG_FILE}")"

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"
PACKAGES_DIR="${SCRIPT_PATH}/packages/"
LIBRARY="${SCRIPT_PATH}/../hammer/library"

LAMBDAS="ami-info logs-forwarder ddb-tables-backup sg-issues-identification s3-acl-issues-identification s3-policy-issues-identification iam-keyrotation-issues-identification iam-user-inactive-keys-identification cloudtrails-issues-identification ebs-unencrypted-volume-identification ebs-public-snapshots-identification rds-public-snapshots-identification sqs-public-policy-identification s3-unencrypted-bucket-issues-identification rds-unencrypted-instance-identification ami-public-access-issues-identification api"

pushd "${SCRIPT_PATH}" > /dev/null
pushd ../hammer/identification/lambdas > /dev/null

DEPS_TEMP=$(mktemp -d)
pip install --target="${DEPS_TEMP}" --no-compile --quiet -r requirements.txt
rm -rf "${DEPS_TEMP}"/*.dist-info
cp -a "${LIBRARY}" "${DEPS_TEMP}/"
cp "${CONFIG_DIR}"/* "${DEPS_TEMP}/"

for lambda in ${LAMBDAS}; do
    TEMP=$(mktemp -d)
    cp -a "${DEPS_TEMP}"/* "${TEMP}/"
    cp -a "${lambda}"/* "${TEMP}/"
    pushd "${TEMP}" > /dev/null
    if [ -f "requirements.txt" ]; then
        pip install --target=. --no-compile --quiet -r requirements.txt
        rm -rf *.dist-info
    fi
    rm -f "${PACKAGES_DIR}/${lambda}.zip"
    # touch all files with predifined timestamp
    # to have archive with the same md5 for not changed sources
    # this prevents updating stack on each deploy
    find . -print0 | xargs -0 touch -t 198105290101.00
    zip -r6 -q --strip-extra "${PACKAGES_DIR}/${lambda}.zip" . --exclude=\*.pyc --exclude=\*__pycache__\*
    # before "${TEMP}"
    popd > /dev/null
    rm -rf "${TEMP}"
done

rm -rf "${DEPS_TEMP}"

# before ../hammer/identification/lambdas
popd > /dev/null

TEMP=$(mktemp -d)
cp -a ../hammer/reporting-remediation/* "${TEMP}/"
cp "${CONFIG_DIR}"/* "${TEMP}/"
cp -a "${LIBRARY}" "${TEMP}/"
pushd "${TEMP}" > /dev/null
rm -f "${PACKAGES_DIR}/reporting-remediation.zip"
find . -print0 | xargs -0 touch -t 198105290101.00
zip -r6 -q --strip-extra "${PACKAGES_DIR}/reporting-remediation.zip" . --exclude=\*.pyc --exclude=\*__pycache__\*
# before "${TEMP}"
popd > /dev/null
rm -rf "${TEMP}"

# before "${SCRIPT_PATH}"
popd > /dev/null
