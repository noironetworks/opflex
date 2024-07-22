#!/bin/bash

set -x
#TODO: add verification
#TODO: add release signing

# Ensure the script is called with the correct number of arguments
if [ "$#" -ne 4 ]; then
    #echo "Usage: <rpm_path> <base64_vault_role> <base64_vault_sec> <build_user1> <build_user2>"
    exit 1
fi

# Define the RPM directories
RPM_DIR_PATH=$(find "$1" -type d -name "*opflexrpms*" | grep "${BUILD_NUMBER}")
#RPM_DIR_PATH=$(find "$1" -type d -name "*opflexrpms*" | grep "19")
if [ -z "$RPM_DIR_PATH" ]; then
    echo "No RPM directory found for build number ${BUILD_NUMBER}"
    exit 1
fi
#NOARCH_DIR="$RPM_DIR/RPMS/noarch"
#SRPMS_DIR="$RPM_DIR/SRPMS"

# Setup Vault
VAULT_ADDR="https://keeper.cisco.com"
VAULT_NAMESPACE="swims-prod/GROUP_2"
VAULT_ROLE_ID=$KEEPER_ROLE_ID
VAULT_SECRET_ID=$KEEPER_SECRET

# Signing CECs
USER1=$2
USER2=$3
# Release Signing or not
RELEASE=$4
# Constants from Travis CI environment variables
BRANCH_NAME=$GIT_BRANCH
PROJECT_NAME=$GIT_URL

# Variables
REPO_URL="https://wwwin-github.cisco.com/STO-Image-Signing/rpm_deb_signing.git"
SIGNHELPER_DIR="$WORKSPACE/rpmbuild"
RPM_DEB_SIGN="$WORKSPACE/rpmbuild/rpm_deb_signing"
CODE_SIGN_EXEC="$RPM_DEB_SIGN/Linux-64/swims-openpgp/code_sign.x86_64"
RPM_SIGN_SCRIPTDIR="$RPM_DEB_SIGN/Linux-64/swims-openpgp"
RPM_BATCH_SIGN="$RPM_SIGN_SCRIPTDIR/rpm_sign_batchmode.py3"
RUN_EXT_SIGN="$RPM_SIGN_SCRIPTDIR/run-extsign"
RPMMACROS="$WORKSPACE/signedRPMS"

WORKING_DIR="$WORKSPACE/SIGNRPMS"
OUTPUT_TOKEN="$WORKING_DIR/dcn-bld.tkn"
LOG_FILE="$WORKING_DIR/swims-session-token.log"

PAYLOAD_OUTPUT="$WORKING_DIR/requestPayload.out3"
SIGNATURE_OUTPUT="$WORKING_DIR/requestPayload.sig3"
SESSION_TOKEN_OUTPUT="$WORKING_DIR/build-session.tkn"

REASON="CLI Test #1"
BUILD_INITIATOR=$USER1
BUILD_TYPE="DEV"
ATTESTATION_KEY_NAME="dcn-plugin-build"
PRODUCT="dcn-container-vm-plugins"
AUTH_TYPE="OTP"
USERNAME=$USER1
PASSWORD="push"

# Step 0: Clone the repository if it does not exist and navigate into it
mkdir -p $SIGNHELPER_DIR
rm -rf $RPM_DEB_SIGN
git clone $REPO_URL $RPM_DEB_SIGN

mkdir -p $WORKING_DIR

# Find RPM files in the RPM directory
RPM_FILES=$(find "$RPM_DIR_PATH" -type f -name "*.rpm")

if [ -z "$RPM_FILES" ]; then
    echo "No RPM files found to sign in $RPM_DIR_PATH"
    exit 1
fi

# Define the CSV file path
CSV_FILE="$SIGNHELPER_DIR/rpm_files.csv"
# Ensure csv is empty
> "$CSV_FILE"
# Append RPM file paths to the CSV file
for RPM_FILE in $RPM_FILES; do
    echo "$RPM_FILE" >> "$CSV_FILE"
done

# Step 1: Create build authorization token
$CODE_SIGN_EXEC swims build authorization create -product $PRODUCT -buildType $BUILD_TYPE \
    -attestationKeyName $ATTESTATION_KEY_NAME -reason "$REASON" -buildInitiators $BUILD_INITIATOR \
    -authType $AUTH_TYPE -username1 $USERNAME -password1 $PASSWORD -out $OUTPUT_TOKEN -logFile $LOG_FILE

# Step 2: Encode payload for build session
$CODE_SIGN_EXEC swims build session encodePayload -buildInitiator $BUILD_INITIATOR -branchName $BRANCH_NAME \
    -projectName $PROJECT_NAME -buildAuthToken $OUTPUT_TOKEN -out $PAYLOAD_OUTPUT -logFile $LOG_FILE

# Step 3: Set Vault environment variables
export VAULT_ADDR=$VAULT_ADDR
export VAULT_NAMESPACE=$VAULT_NAMESPACE
export VAULT_ROLE_ID=$VAULT_ROLE_ID
export VAULT_SECRET_ID=$VAULT_SECRET_ID

# Step 4: Sign the payload with attestation key
$CODE_SIGN_EXEC swims utils vault signWithAttestationKey -attestationKeyName $ATTESTATION_KEY_NAME \
    -input $PAYLOAD_OUTPUT -out $SIGNATURE_OUTPUT -logFile $LOG_FILE

# Step 5: Create build session token
$CODE_SIGN_EXEC swims build session create -requestPayload $PAYLOAD_OUTPUT -requestSignature $SIGNATURE_OUTPUT \
    -out $SESSION_TOKEN_OUTPUT -logFile $LOG_FILE

# Print completion message
echo "Build session token created successfully and stored in $SESSION_TOKEN_OUTPUT"

export SWIMS_SESSION_TOKEN=$SESSION_TOKEN_OUTPUT
source $WORKSPACE/docker/rpms/my_setup_dev.sh $CODE_SIGN_EXEC $USER1
cd $RPM_SIGN_SCRIPTDIR
./run-make-cert.exp
gpg --import dev.gpg
#gpg --list-keys

# Create the ~/.rpmmacros file with the specified configuration
cat >"$WORKING_DIR/.rpmmacros" <<EOF
%_gpg_name      _
%__gpg_check_password_cmd       /bin/true
%__gpg_sign_cmd                 $RUN_EXT_SIGN \\
        run-extsign %{__plaintext_filename} %{__signature_filename}
EOF

python3 $RPM_BATCH_SIGN -f $CSV_FILE -m $WORKING_DIR/.rpmmacros

#rm -rf $WORKING_DIR