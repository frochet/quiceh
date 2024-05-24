#!/bin/bash
set -e

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

QUICHE_DIR=/quiceh
WWW_DIR=/www
DOWNLOAD_DIR=/downloads
QUICHE_CLIENT=quiceh-client
QUICHE_SERVER=quiceh-server
QUICHE_CLIENT_OPT="--no-verify --dump-responses ${DOWNLOAD_DIR} --wire-version 00000003"
# interop container has tso off. need to disable gso as well.
QUICHE_SERVER_OPT_COMMON="--listen [::]:443 --root $WWW_DIR --cert /certs/cert.pem --key /certs/priv.key --disable-gso --disable-pacing"
QUICHE_SERVER_OPT="$QUICHE_SERVER_OPT_COMMON --no-retry "
LOG_DIR=/logs
LOG=$LOG_DIR/log.txt

check_testcase () {
    case $1 in
        handshake | multiconnect | http3 )
            echo "supported"
            ;;

        transfer )
            echo "supported"
            ;;

        chacha20 )
            if [ "$ROLE" == "client" ]; then
                # We don't support selecting a cipher on the client-side.
                echo "unsupported"
                exit 127
            elif [ "$ROLE" == "server" ]; then
                echo "supported"
            fi
            ;;

        resumption )
            echo "supported"
            QUICHE_CLIENT_OPT="$QUICHE_CLIENT_OPT --session-file=session.bin"
            ;;

        zerortt )
            if [ "$ROLE" == "client" ]; then
                echo "supported"
                QUICHE_CLIENT_OPT="$QUICHE_CLIENT_OPT --session-file=session.bin --early-data"
            elif [ "$ROLE" == "server" ]; then
                echo "supported"
                QUICHE_SERVER_OPT="$QUICHE_SERVER_OPT --early-data"
            fi
            ;;

        retry )
            echo "supported"
            QUICHE_SERVER_OPT="$QUICHE_SERVER_OPT_COMMON"
            ;;

        *)
            echo "unsupported"
            exit 127
            ;;

    esac
}

run_quiceh_client_tests () {
    # TODO: https://github.com/marten-seemann/quic-interop-runner/issues/61
    # remove this sleep when the issue above is resolved.
    sleep 3

    case $1 in
        multiconnect )
            for req in $REQUESTS
            do
                $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
                    $CLIENT_PARAMS $req >> $LOG 2>&1
            done
            ;;

        resumption | zerortt )
            REQS=($REQUESTS)

            # Run first request in 1-RTT to establish session.
            FIRST_REQUEST=${REQS[0]}

            $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
                $CLIENT_PARAMS $FIRST_REQUEST >> $LOG 2>&1

            # Run remaining requests in resumed connection.
            REMAINING_REQUESTS=${REQS[@]:1}

            $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
                $CLIENT_PARAMS $REMAINING_REQUESTS >& $LOG 2>&1

            ;;

        *)
            $QUICHE_DIR/$QUICHE_CLIENT $QUICHE_CLIENT_OPT \
                $CLIENT_PARAMS $REQUESTS >& $LOG
            ;;

    esac
}

run_quiceh_server_tests() {
    $QUICHE_DIR/$QUICHE_SERVER $SERVER_PARAMS $QUICHE_SERVER_OPT >& $LOG
}

# Update config based on test case
check_testcase $TESTCASE

# Create quiceh log directory
mkdir -p $LOG_DIR

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    /wait-for-it.sh sim:57832 -s -t 30
    echo "## Starting quiceh client..."
    echo "## Client params: $CLIENT_PARAMS"
    echo "## Requests: $REQUESTS"
    echo "## Test case: $TESTCASE"
    run_quiceh_client_tests $TESTCASE
elif [ "$ROLE" == "server" ]; then
    echo "## Starting quiceh server..."
    echo "## Server params: $SERVER_PARAMS"
    echo "## Test case: $TESTCASE"
    run_quiceh_server_tests
fi
