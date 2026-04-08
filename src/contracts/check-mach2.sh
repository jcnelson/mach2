#!/bin/bash

set -uoe pipefail

test -d /tmp/check-mach2.db && rm -rf /tmp/check-mach2.db

# CLARITY_CLI="clarity-cli"
CLARITY_CLI="./clarity-cli"

"${CLARITY_CLI}" initialize /tmp/check-mach2.db
"${CLARITY_CLI}" check ./bitcoin.clar --contract-id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.bitcoin
"${CLARITY_CLI}" launch SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.bitcoin ./bitcoin.clar /tmp/check-mach2.db

"${CLARITY_CLI}" check ./segwit.clar --contract-id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/check-mach2.db
"${CLARITY_CLI}" check ./witness.clar --contract-id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/check-mach2.db

cat ./outcomes.clar ./segwit.clar ./witness.clar ./mach2.clar > /tmp/outcomes.clar
"${CLARITY_CLI}" check /tmp/outcomes.clar --contract-id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/check-mach2.db

cat ./segwit.clar ./witness.clar ./outcomes.clar ./mach2.clar > /tmp/mach2.clar
echo "" >> /tmp/mach2.clar
echo "$@" >> /tmp/mach2.clar

"${CLARITY_CLI}" check /tmp/mach2.clar --contract-id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/check-mach2.db
"${CLARITY_CLI}" launch SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/mach2.clar /tmp/check-mach2.db

