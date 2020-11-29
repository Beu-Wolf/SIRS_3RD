#!/bin/sh

# SERVER=Server/keys
SERVER_PATH=Server/keys
BACKUP_PATH=Backup/keys
CLIENT_PATH=Client/keys
CA_PATH=CA

rm -rf $SERVER_PATH $BACKUP_PATH $CLIENT_PATH $CA_PATH

SERVER_KEYSTORE="$SERVER_PATH/server.keystore.pk12"
BACKUP_KEYSTORE="$BACKUP_PATH/backup.keystore.pk12"
CLIENT_KEYSTORE="$CLIENT_PATH/client.keystore.pk12"

SERVER_TRUSTSTORE_FOR_CLIENT="$SERVER_PATH/server_client.truststore.pk12"
SERVER_TRUSTSTORE_FOR_BACKUP="$SERVER_PATH/server_backup.truststore.pk12"
BACKUP_TRUSTSTORE="$BACKUP_PATH/backup.truststore.pk12"
CLIENT_TRUSTSTORE="$CLIENT_PATH/client.truststore.pk12"

SERVER_ALIAS="server"
BACKUP_ALIAS="backup"
CLIENT_ALIAS="client"

STOREPASS=changeit

mkdir -p $SERVER_PATH
mkdir -p $BACKUP_PATH
mkdir -p $CLIENT_PATH
mkdir -p $CA_PATH

genkeypair() {
    KEYSTORE=$1
    ALIAS=$2

    keytool -genkeypair -keystore $KEYSTORE -alias $ALIAS -keyalg RSA \
            -validity 365 -storetype PKCS12 -keysize 2048 \
            -storepass $STOREPASS \
            -dname "CN=$ALIAS,OU=SIRS,O=IST,L=Lisbon,ST=Lisbon,C=PT"
}

genkeypair $SERVER_KEYSTORE $SERVER_ALIAS
genkeypair $BACKUP_KEYSTORE $BACKUP_ALIAS
genkeypair $CLIENT_KEYSTORE $CLIENT_ALIAS

genca() {
    CN=$1
    CERT=$2
    KEY=$2.key
    SERIAL=$2.srl

    openssl req -new -x509 -newkey rsa:2048 -keyout $KEY \
                -out $CERT -days 365 -passout pass:$STOREPASS \
                -subj "/CN=$CN/OU=SIRS/O=IST/L=Lisbon/ST=Lisbon/C=PT"
    echo 01 > $SERIAL
}

SERVER_CA=$CA_PATH/server-ca
CLIENT_CA=$CA_PATH/client-ca

SERVER_CA_ALIAS=server-ca
CLIENT_CA_ALIAS=client-ca

genca server-ca $SERVER_CA
genca client-ca $CLIENT_CA

signcert() {
    KEYSTORE=$1
    ALIAS=$2
    CA=$3
    CA_ALIAS=$4
    CA_KEY=$CA.key
    TMP_CSR=__tosign.csr
    TMP_CRT=__signed.crt

    keytool -keystore $KEYSTORE -alias $ALIAS -certreq \
            -storepass $STOREPASS -file $TMP_CSR

    openssl x509 -req -CA $CA -CAkey $CA_KEY -days 365 \
                 -in $TMP_CSR -out $TMP_CRT -passin pass:$STOREPASS \
                 -CAcreateserial

    keytool -keystore $KEYSTORE -alias $CA_ALIAS -importcert \
            -noprompt -storepass $STOREPASS -file $CA

    keytool -keystore $KEYSTORE -alias $ALIAS -importcert \
            -noprompt -storepass $STOREPASS -file $TMP_CRT

    rm $TMP_CSR $TMP_CRT
}

signcert $CLIENT_KEYSTORE $CLIENT_ALIAS $CLIENT_CA $CLIENT_CA_ALIAS
signcert $SERVER_KEYSTORE $SERVER_ALIAS $SERVER_CA $SERVER_CA_ALIAS
signcert $BACKUP_KEYSTORE $BACKUP_ALIAS $SERVER_CA $SERVER_CA_ALIAS

trust() {
    TRUSTSTORE=$1
    CA=$2
    CA_ALIAS=$3

    keytool -keystore $TRUSTSTORE -alias $CA_ALIAS -importcert \
            -noprompt -storepass $STOREPASS -file $CA
}

trust $CLIENT_TRUSTSTORE $CLIENT_CA $CLIENT_CA_ALIAS
trust $CLIENT_TRUSTSTORE $SERVER_CA $SERVER_CA_ALIAS

trust $SERVER_TRUSTSTORE_FOR_CLIENT $CLIENT_CA $CLIENT_CA_ALIAS
trust $SERVER_TRUSTSTORE_FOR_BACKUP $SERVER_CA $SERVER_CA_ALIAS

trust $BACKUP_TRUSTSTORE $SERVER_CA $SERVER_CA_ALIAS
