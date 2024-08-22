# shellcheck disable=all
set -a
  
# if dev=1, then we recompile tools before each invocation, even if binaries already exist (not recommended for signing users)
dev=0

# If you are running rpm signing tools from a daemon process, set the Environment Variable RPM_SIGN_DAEMON=1, otherwise leave it unset.
# This will prevent output to a tty, which doesn't exist on a daemon process
#RPM_SIGN_DAEMON=1

## Use ./signContent-swims for SWIMS
signing_helper=./signContent-swims

key_creation_time=1 # If set to 1, a timestamp of current time will be added to the signature in the public key file, otherwise
                    # a static timestamp of "2017-Jan-01" will be used (when set to 0)

sig_creation_time=0 # If set to 0, or not set, a timestamp of current time will be added to the signature file (common case).
                    # If set to 1, a static timestamp (of 2017-Jan-02)  will be added to the signature file. This
                    #    aligns with the 'key_creation_time' timestamp setting above, the key must be equal to or of older age than the
                    #    signature to verify successfully.
                    # If set to > 0, it is assumed to be seconds since the epoch, 1970-01-01 00:00:00 UTC
                    #    This value can typically be determined using the date unix command for a particular date, e.g.
                    #     $ date --date='2018-01-01' +%s
                    #       1514782800
                    #
                    #     $ date --date='2021-07-11 11:43:40' +%s
                    #       1626018220


## comment these out to use the production SWIMS server
#swims_certfile=                                # if set, alternate cert to validate host, typically don't use
#swims_host='swims-stg-aln.cisco.com'           # if set, alternate host to use

swims_client_log="swims_client.log"

#For the swims_client command, you have options:
#   1) For newer 64-bit machines (e.g. RHEL7, RHEL8, Ubuntu16, ubuntu18, Ubuntu20, and future), use the code_sign7.x86_64 executable provided in this repo (built on py3 RHEL7)
#   2) For python2 and/or older 64-bit machines (e.g. CentOs6, CEL6, etc), use the code_sign.x86_64 executable provided in this repo
#   3) For 32-bit machines, use the code_sign6_32 executable provided in this repo
#   4) Use your own code_sign executable copy (not recommended), provide the path to it
#   5) A copy of the swims_client.py script (see below) 

#This example uses option 1, always include the keyword 'swims' (except for option 5)
swims_client_cmd=$1' swims'
#swims_client_cmd="$PWD"'/code_sign.x86_64 swims'

## un-comment this to use option 5, a swims_client.py python script (not provided in repo)
##swims_client_cmd='python swims_client.py'     # eval-able string

sig_type=dev            # must be either "dev" or "rel"
#gpgkeydir=<path to the directory to store/retrieve the gpg key> # if you want to create the gpgkey (i.e. run-make-cert) into or retrieve the gpgkey from someplace other than
                                                                 # this scripts directory, set this parameter to the directory path only.  Otherwise don't set. Include final
                                                                 # slash if you do set it, e.g. /tmp/ . The keys must be named rel.gpg or dev.gpg regardless.

user1=$2         # CEC name; only user required for dev signatures
pass1=push              # For DUO push request

notes="RPM Test for ISC"

#Generic userid can be used for DEV signing
#generic_user=          # generic user id 
#generic_pw=            # generic user password

# To use tickets rather than OTP (for SWIMS), specify the ticket_file path
# e.g. ticket_file=/home/swims/RPM/rpm_deb_signing-master/Linux-64/swims-openpgp/myticket
#ticket_file=<path to ticket>   # if this is specified, use a ticket rather than OTP (for SWIMS)
#ticket_file=/home/swims/repo-rpm-deb-sign-src/rpm_deb_sign_src/Linux-64/swims-openpgp/mph-2987471-DEV-ticket

# To use session tokens, use the SWIMS_SESSION_TOKEN and SWIMS_TREAT_TICKET_AS_TOKEN Environment Variables.  See 
# https://docs.cisco.com/share/page/site/nextgen-edcs/document-details?nodeRef=workspace://SpacesStore/44769d41-9bb4-4a4e-b6c1-cbfd1a7184a1 for more details.

# If using a token, "SWIMS_SESSION_TOKEN" must be set to the raw token string or the path to the file containing the token.
#SWIMS_SESSION_TOKEN=/tmp/build-session.tkn
# If using a token for a legacy build script that cannot easily utilize the "SWIMS_SESSION_TOKEN" variable,
# the "ticket_file" variable must be set to the path to the file containing the token,
# and "SWIMS_TREAT_TICKET_AS_TOKEN" must be set to "True."
#SWIMS_TREAT_TICKET_AS_TOKEN=True

# User provided encoded JSON string or file path to the file containing the encoded JSON string that includes 
# all mandatory and optional build or artifact metadata regarding the build session. (See code_sign tool: "code_sign build-data -h")
#BUILD_METADATA=
#ARTIFACT_METADATA=

product=dcn-container-vm-plugins                # Product name (also key name for Abraxas, which only has one key for product)
product_key=dcn-container-vm-keys-dev   # Key name for SWIMS (defaults to product name if not given)
#product_pid=testPid            # PID for SWIMS; if commented out, no PID will be given. If your PID is not marked as 'Real Pid' in your Product Entry in SWIMs, don't set this.

#armored_pgp_sig=yes             # Uncomment to make run-extsign produce an armored base64 gpg signature file

#If you are using GRUB2 to verify gpg signatures for files (e.g. the kernel), then the file must be signed with RPM_MAJOR_VERSION = 5. This allows the key id to be placed 
#in the unhashed sub-components within the signature, which GRUB2 currently expects.
#RPM_MAJOR_VERSION = 5

## Customer-visible identity for "who signed this code?"
# Do not include invalid characters like '\x00', '(', ')', '<' and '>' in <identity_*> fields
identity_name=$2
identity_email=$2'@cisco.com'
#identity_comment="${product}.${sig_type}"      # if commented out / undefined, default will be built per this pattern

set +a

# vim: filetype=sh