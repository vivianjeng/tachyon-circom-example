#!/bin/bash

# Define the URL of the file to download
url="https://ci-keys.zkmopro.org/main_final.zkey"

# Define the destination path to save the downloaded file
destination="./circuits/rsa/rsa_main.zkey"

# Download the file using curl
curl -o "$destination" "$url"

# Check if the download was successful
if [ $? -eq 0 ]; then
    echo "Download completed successfully."
else
    echo "Download failed."
fi