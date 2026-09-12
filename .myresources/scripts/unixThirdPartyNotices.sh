#!/bin/bash

# UNIX GENERATING THIRD_PARTY_NOTICES.TXT
echo -e "\033[0;32m"
echo "          ▒▒▒▒▒"
echo "         ▒▒▒▒▒▒▒"
echo "         ▒▒▒▒▒▒▒▒"
echo "         ▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒"
echo "         ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒"
echo "    ▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒    ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓  ▓▓▓▓▓▓    ▓▓▓▓     ▓▓▓▓▓▓ ▓▓▓▓▓▓▓"
echo " ▒▒▒▒▒▒▒▒▒▒▓▓▓███▓▓▓▒▒▒▒▒▒▒     ▓▓▓     ▓▓▓  ▓▓▓ ▓▓▓       ▓▓▓   ▓▓▓▓      ▓▓▓▓▓     ▓▓▓    ▓▓▓ ▓▓▓"
echo " ▒▒▒▒▒▒▒▒▒▓▓▓█████▓▓▓▒▒▒▒▒      ▓▓▓▓▓▓  ▓▓    ▓▓ ▓▓▓▓▓▓    ▓▓▓   ▓▓▓▓▓▓▓ ▓▓▓ ▓▓▓     ▓▓▓▓▓▓ ▓▓▓▓▓▓"
echo "  ▒▒▒▒▒▒▒▒▓▓▓█████▓▓▓▒▒▒▒▒         ▓▓▓▓ ▓▓▓  ▓▓▓ ▓▓▓       ▓▓▓   ▓▓▓ ▓▓▓ ▓▓▓▓▓▓▓▓    ▓▓▓    ▓▓▓ ▓▓▓"
echo "    ▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒     ▓▓▓▓▓▓▓ ▓▓▓▓▓▓▓▓ ▓▓▓       ▓▓▓   ▓▓▓▓▓▓▓     ▓▓▓  ▓▓ ▓▓▓    ▓▓▓  ▓▓▓"
echo "        ▒▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▒▒▒"
echo "       ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒"
echo "       ▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒"
echo "       ▒▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒"
echo "        ▒▒▒▒▒"
echo -e "\033[0m"

echo "####################################################################################################"
echo "#                                     GENERATING THIRD_PARTY_NOTICES.TXT                           #"
echo "####################################################################################################"
echo ""

NOTICES_EDIT="THIRD_PARTY_NOTICES_TO_EDIT.txt"
THIRD_PARTY="target/generated-sources/license/THIRD-PARTY.txt"
OUTPUT="THIRD_PARTY_NOTICES.txt"

if [ ! -f "$NOTICES_EDIT" ]; then
    echo "Missing: $NOTICES_EDIT"
elif [ ! -f "$THIRD_PARTY" ]; then
    echo "Missing: $THIRD_PARTY"
else
    rm -f "$OUTPUT"
    cat "$NOTICES_EDIT" "$THIRD_PARTY" > "$OUTPUT"
    echo "$OUTPUT successfully generated."
fi

echo ""
echo "####################################################################################################"
echo "#                                              DONE !                                              #"
echo "####################################################################################################"
