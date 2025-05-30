
This document explains how to produce the core results of the related
paper "Contiguous Zero-Copy for Encrypted Transport Protocols". This
document gives reproducibility steps that should work for any
Linux-based distribution.

# Installing Rust

Follow the guideline provided
[here](https://www.rust-lang.org/tools/install) to install rustc (the
compiler), cargo (the package manager) and the other Rust tools.

# Reproducing Data for Figure 3.

The first step is to clone the repository and prepare the binaries by
compiling the benchmarks on the default branch (protocol_reverso). You
would need multiple GBs of disk space to install and compile all
dependencies. Run the following commands within the repository root to
prepare the binaries:

$ cargo bench --bench initial_cwin_bench --no-run

$ cargo bench --bench initial_cwin_bench --profile performance --no-run

$ cargo bench --bench quic_benchmarks --no-run

$ cargo bench --bench h3_benchmarks --no-run

$ cargi bench --bench h3_benchmarks --profile performance --no-run

For each of Figure a, b and c, we run bench code at the nominal
frequency of our machine to get the necessary data contained within
these plots. Make sure you have the utility cpupower installed, get the
nominal frequency value of your processor, the MIN and MAX frequency
values, and adapt one of the .sh scripts, such as bench_i71165.sh given
in the root of the repository and containing the following:

``` bash
MIN=400MHz
MAX=4700MHz
SET_MIN=2799MHz
SET_MAX=2800MHz
BENCH=$1
PROFILE=$2

sudo cpupower -c 0 frequency-set -d $SET_MIN -u $SET_MAX -g performance
taskset -c 0 cargo bench --bench $BENCH --profile $PROFILE
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave
```

Replace MIN, MAX, SET_MIN, SET_MAX accordingly to your processor. Make
sure that powersave is indeed the configuration you wish at the end of
the experiment.

You'll need super user rights to use it. Give your file the executable
right (chmod +x [your_file_name].sh).

## Data for Figure 3.a

Make sure your machine is idle (quit any userland program), and then run
your modified .sh script:

./[your_file_name].sh initial_cwin_bench release

This will run the benchmark for figure 3(a) and give you two values, one
for QUIC v1 and one for QUIC VReverso on a release compilation build.

Run as well the fat LTO compilation build:

./[you_file_name.sh initial_cwin_bench performance

Repeat this procedure on any CPU.

## Data for Figure 3.b

Make sure your machine is idle (quit any userland program), and then run
your modified .sh script:

./[your_file_name].sh quich_benchmarks release

this will create one datapoint for each of QUIC v1 and QUIC VReverso for
several data size.

## Data for Figure 3.c


Make sure your machine is idle (quit any userland program), and then run
your modified .sh script:

./[your_file_name].sh h3_benchmarks release

This will run the benchmark for figure 3(a) and give you two values, one
for QUIC v1 and one for QUIC VReverso on a release compilation build.

Run as well the fat LTO compilation build:

./[you_file_name.sh h3_benchmarks performance

Repeat this procedure on any CPU.

# Reproducing Table 2.

Table 2 contains real-world measurements of ordered packets from
computers around the world. You may reproduce similar results by running
a server on some location, and a script provided below on another
location. First, switch branch to "measurements"

$ git checkout measurements

build the code in release mode on the client and the server machines.

$ cargo build --release

Create a 2.5MiB file on the server machine you intend to use for the
measurement, in the root of the the quiceh repository cloned to that
machine:

$ dd if=/dev/zero of=2-5MiB bs=1024 count=2560

Run the server on the server machine:

$ ./target/release/quiceh-server --listen PUBIP:PORT --key apps/src/bin/cert.key --cert apps/src/bin/cert.crt --root .


On the client machine, still in the measurements branch, you'll find a
script named ordering_measurements.sh containing:

``` bash
DESTIPPORT=$1
DIRECTORY=$2

mkdir -p $DIRECTORY

# 00791097
for i in {1..20}
do
  RUST_LOG=quiceh=warn ./target/release/quiceh-client --wire-version 00791097 $DESTIPPORT --no-verify 2> $DIRECTORY/$i
done
```

Run the script as follows:

./ordering_measurements https://SERVERIP:SERVERPORT/2-5MiB
DIRECTORY_NAME

Where SERVERIP is your server IP or domain name, and SERVERPORT should
be the one used in quiceh-server's --listen argument.

The script will download the 2.5MiB file 20 times, and store logs for
each download within DIRECTORY_NAME. A given logfile would contain one
line for each received packet:

```
[2024-09-02T13:07:30.873239489Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.873241097Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.873242715Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.873244295Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.873245971Z WARN  quiceh] Not in order: attaching a copy at offset 999962
[2024-09-02T13:07:30.873248958Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.906021238Z WARN  quiceh] Recv in order. No copy needed
[2024-09-02T13:07:30.906042135Z WARN  quiceh] Recv in order. No copy needed
```

Counting packets in order for the 20 downloads would give you a similar
result than a cell within Table 2.

# Data for Figure 4.

Reproducing similar data than figure 4 requires a 1 Gbps link between a
client and a server. The experiment within the paper connects a desktop
machine to a lab server on copper gbps, gbps middleboxes and small
distance (below 100m).

For the server, you may run any branch, and similar to the above server
instructions, run quiceh-server:

$ ./target/release/quiceh-server --listen PUBIP:PORT --key apps/src/bin/cert.key --cert apps/src/bin/cert.crt --root .

Create a 10 Gb file.

For the client, switch on the "measurements" branch. Modify the
following script named measure_dl_i71165.sh and available in the root of
the repository accordingly to the frequency values of your processor.
Replace also the server address
(https://reverso.info.unamur.be:4433/testfile) with your domain or IP +
port, and 10Gb file.

```bash
MIN=400MHz
MAX=4700MHz
SET_MIN=2800MHz
SET_MAX=2800MHz
VERSION=$1
DIRECTORY=$2
OUTNAME=$3

mkdir -p $DIRECTORY

sudo cpupower -c 0 frequency-set -d $SET_MIN -u $SET_MAX -g performance
for i in {1..20}
do
  taskset -c 2 sudo perf stat -e cycles,instructions --interval-print 100 -C 0 taskset -c 0 ./target/performance/quiceh-client --wire-version $VERSION --no-verify https://reverso.info.unamur.be:4433/testfile > /dev/null 2> $DIRECTORY/$OUTNAME_$i
done
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave
```

On the measurements branch, you may then get the "Cycles" value by
running the script two times, one for QUIC v1, and one for QUIC VReverso
(the server supports both protocol). First, recompile your client:

$ cargo build --profile performance

For QUIC v1, we could have:

$ ./measure_dl_i71166.sh 1 quicv1_recvmmsg 

For QUIC VReverso, we would have:

$ ./measure_dl_i71166.sh 00791097 quicvreverso_recvmmsg

To get the two lines using recvmsg() instead of recvmmsg(), you may
switch to the branch quiceh_recvmsg.

$ git checkout quiceh_recvmsg

re-compile your client

$ cargo build --profile performance

And re-take the measurements:

$ ./measure_dl_i71166.sh 1 quicv1_recvmsg 

and

$ ./measure_dl_i71166.sh 00791097 quicvreverso_recvmsg

That would make up 4 directories containing each 20 log files from which
data can be extracted and ploted. An example of such a script is given
in 
