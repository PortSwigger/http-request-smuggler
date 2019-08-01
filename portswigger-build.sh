#!/bin/sh
set -ue

alias bapp=../../bapp.sh

cd "`dirname "$0"`"

bapp pull turbo-intruder
bapp build turbo-intruder
cp ../turbo-intruder/build/libs/turbo-intruder-all.jar .
(cd ../turbo-intruder && git reset --hard origin/master && git clean -xfd)
git add turbo-intruder-all.jar
bapp build http-request-smuggler
git reset turbo-intruder-all.jar
