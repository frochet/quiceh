DESTIPPORT=$1
DIRECTORY=$2

mkdir -p $DIRECTORY

# 00791097
for i in {10..20}
do
  RUST_LOG=quiceh=warn ./target/release/quiceh-client --wire-version 00791097 $DESTIPPORT --no-verify 2> $DIRECTORY/$i
done

