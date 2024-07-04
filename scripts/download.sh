#!/bin/bash

# Define the URL of the file to download
rsa_url="https://ci-keys.zkmopro.org/main_final.zkey"

# Define the destination path to save the downloaded file
rsa_destination="./circuits/rsa/rsa_main.zkey"

# Download the file using curl
curl -o "$rsa_destination" "$rsa_url"

# Check if the download was successful
if [ $? -eq 0 ]; then
    echo "Download completed successfully."
else
    echo "Download failed."
fi

# Define the URL of the file to download
keccak_url="https://ci-keys.zkmopro.org/keccak256_256_test_final.zkey"

# Define the destination path to save the downloaded file
keccak_destination="./circuits/keccak256/keccak_main.zkey"

# Download the file using curl
curl -o "$keccak_destination" "$keccak_url"

# Check if the download was successful
if [ $? -eq 0 ]; then
    echo "Download completed successfully."
else
    echo "Download failed."
fi