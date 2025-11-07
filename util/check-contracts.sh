#!/bin/bash

set -uoe pipefail 

DB_PATH="/tmp/m2.db"
CONTRACTS="../src/vm/contracts"

if [ -d "$DB_PATH" ]; then
   rm -r "$DB_PATH"
fi

clarity-cli initialize "$DB_PATH"

function do_checks() {
   local CONTRACT="$1"
   local CONTRACT_BASENAME="$(basename "$CONTRACT")"
   local CONTRACT_NAME="${CONTRACT_BASENAME%%.linked}"
   CONTRACT_NAME="${CONTRACT_NAME%%.clar}"
   local FULL_CONTRACT_NAME="SP000000000000000000002Q6VF78.$CONTRACT_NAME"

   echo "Check $CONTRACT"
   clarity-cli check --contract_id "$FULL_CONTRACT_NAME" "$CONTRACT" "$DB_PATH"

   echo "Launch $CONTRACT"
   clarity-cli launch "$FULL_CONTRACT_NAME" "$CONTRACT" "$DB_PATH"
}

do_checks "$CONTRACTS/m2-ll.clar"
    
cat "$CONTRACTS/m2.clar" > "/tmp/m2-$$.linked"
do_checks "/tmp/m2-$$.linked"
rm "/tmp/m2-$$.linked"

for arg in $@; do
    # link in m2
    cat "$CONTRACTS/m2.clar" > "$arg.linked"
    echo ";; =========== END OF M2 ================" >> "$arg.linked"
    cat "$arg" >> "$arg.linked"
    do_checks "$arg.linked"
done

