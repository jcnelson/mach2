#!/bin/bash

set -uoe pipefail

test -d /tmp/check-mach2.db && rm -rf /tmp/check-mach2.db

CLARITY_CLI="clarity-cli"
# CLARITY_CLI="./clarity-cli"

"${CLARITY_CLI}" initialize /tmp/check-mach2.db
"${CLARITY_CLI}" check ./bitcoin.clar --contract_id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.bitcoin
"${CLARITY_CLI}" launch SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.bitcoin ./bitcoin.clar /tmp/check-mach2.db

"${CLARITY_CLI}" check ./mach2.clar --contract_id SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 /tmp/check-mach2.db
"${CLARITY_CLI}" launch SP3EGRW513CF1TVE4AMSN2WDQRFT6818QJH006B45.mach2 ./mach2.clar /tmp/check-mach2.db
