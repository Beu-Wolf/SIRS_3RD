#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <keys_folder>"
fi

source ./common.sh

CLIENT_PATH="Client/$1"
CLIENT_KEYSTORE="$CLIENT_PATH/client.keystore.pk12"
CLIENT_TRUSTSTORE="$CLIENT_PATH/client.truststore.pk12"
CLIENT_ALIAS="client"

rm -rf $CLIENT_PATH
mkdir -p $CLIENT_PATH

genkeypair $CLIENT_KEYSTORE $CLIENT_ALIAS
signcert $CLIENT_KEYSTORE $CLIENT_ALIAS $CLIENT_CA $CLIENT_CA_ALIAS
trust $CLIENT_TRUSTSTORE $SERVER_CA $SERVER_CA_ALIAS
