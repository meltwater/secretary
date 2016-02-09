#!/bin/sh
set -e

# Decrypt secrets
if [ "$SERVICE_PRIVATE_KEY" != "" ]; then
	SECRETS=$(app decrypt -e "--service-key=$SERVICE_PRIVATE_KEY")
else
	SECRETS=$(app decrypt -e)
fi

eval "$SECRETS"
unset SECRETS

# Start the daemon
exec app "$@"
