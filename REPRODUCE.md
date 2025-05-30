
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

Create a 10 Gb file on the server.

$ dd if=/dev/zero of=10gb count=1000 bs=1000000

For the client, switch on the "measurements" branch. Modify the
following script named measure_dl_i71165.sh and available in the root of
the repository accordingly to the frequency values of your processor.
Replace also the server address
(https://reverso.info.unamur.be:4433/10gb) with your domain or IP +
port, and 10gb filename.

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
  taskset -c 2 sudo perf stat -e cycles,instructions --interval-print 100 -C 0 taskset -c 0 ./target/performance/quiceh-client --wire-version $VERSION --no-verify https://reverso.info.unamur.be:4433/10gb > /dev/null 2> $DIRECTORY/$OUTNAME_$i
done
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave
```

On the measurements branch, you may then get the "Cycles" value by
running the script two times, one for QUIC v1, and one for QUIC VReverso
(the server supports both protocol). First, recompile your client:

$ cargo build --profile performance

For QUIC v1, we could have:

$ ./measure_dl_i71165.sh 1 quicv1_recvmmsg 

For QUIC VReverso, we would have:

$ ./measure_dl_i71165.sh 00791097 quicvreverso_recvmmsg

To get the two lines using recvmsg() instead of recvmmsg(), you may
switch to the branch quiceh_recvmsg.

$ git checkout quiceh_recvmsg

re-compile your client

$ cargo build --profile performance

And re-take the measurements:

$ ./measure_dl_i71165.sh 1 quicv1_recvmsg 

and

$ ./measure_dl_i71165.sh 00791097 quicvreverso_recvmsg

That would make up 4 directories containing each 20 log files from which
data can be extracted and ploted. An example of such a script assuming
the nominal value is 2800MHz:

``` python
import os
import matplotlib
import matplotlib.pyplot as plt
import pdb
import numpy as np
import scipy.stats as stats
matplotlib.rcParams.update({'font.size': 22})

def parse_file(file_path):
    times = np.linspace(0, 10, 101)
    cycles = []

    with open(file_path, 'r') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3 and parts[2] == 'cycles':
                cycles.append(int(parts[1].replace('.', '')))

    return times, cycles

def calculate_cpu_utilization(cycles, interval_duration, cpu_frequency):
    max_possible_cycles = cpu_frequency * interval_duration
    utilizations = [(cycle_count / max_possible_cycles) * 100 for cycle_count in cycles]
    return utilizations

def process_files(file_paths, cpu_frequency):
    all_data = {}

    for file_path in file_paths:
        times, cycles = parse_file(file_path)
        if len(times) > 1:  # Ensure there is at least one interval to compute
            for i in range(1, len(times)):
                interval_duration = times[i] - times[i-1]
                if i < len(cycles):
                    utilization = calculate_cpu_utilization([cycles[i]], interval_duration, cpu_frequency)[0]

                    if times[i] not in all_data:
                        all_data[times[i]] = []
                    all_data[times[i]].append(utilization)
                else:
                    break

    return all_data

def calculate_mean_confidence_interval(data, confidence=0.95):
    avg_data = {}
    conf_int = {}
    for time, utilizations in data.items():
        data = np.array(utilizations)

        mean = np.mean(data)

        #Calculate the standard error of the mean (SEM)
        sem = stats.sem(data)

        #Determine the t-value for the given confidence level and sample size
        n = len(data)
        t_value = stats.t.ppf((1 + confidence) / 2.0, n - 1)

        margin_of_error = t_value * sem

        conf_interval = (mean - margin_of_error, mean + margin_of_error)

        avg_data[time] = mean
        conf_int[time] = conf_interval

    return avg_data, conf_int

def plot_utilization(avg_data, avg_data2, avg_data3, avg_data4, conf_int,
                     conf_int2, conf_int3, conf_int4):
    times = sorted(avg_data.keys())
    utilizations = [avg_data[time] for time in times]
    util_int_low = [conf_int[time][0] for time in times]
    util_int_up = [conf_int[time][1] for time in times]
    util2 = [avg_data2[time] for time in times]
    util2_int_low = [conf_int2[time][0] for time in times]
    util2_int_up = [conf_int2[time][1] for time in times]
    util3 = [avg_data3[time] for time in times]
    util3_int_low = [conf_int3[time][0] for time in times]
    util3_int_up = [conf_int3[time][1] for time in times]
    util4 = [avg_data4[time] for time in times]
    util4_int_low = [conf_int4[time][0] for time in times]
    util4_int_up = [conf_int4[time][1] for time in times]

    plt.figure(figsize=(10, 6))
    plt.plot(times, utilizations, marker='o', linestyle='-', color='b', label="recvmmsg() + HTTP/3 with QUIC V1")
    ax = plt.gca()
    ax.fill_between(times, util_int_low, util_int_up, color="b", alpha=.2)
    plt.plot(times, util2, marker='*', linestyle='-', color='r', label="recvmmsg() + HTTP/3 with QUIC VReverso")
    ax.fill_between(times, util2_int_low, util2_int_up, color="r", alpha=.2)
    plt.plot(times, util3, marker="x", linestyle="-.", color="black", label="recvmsg() + HTTP/3 with QUIC V1")
    ax.fill_between(times, util3_int_low, util3_int_up, color="black", alpha=.2)
    plt.plot(times, util4, marker="+", linestyle="--", color="cyan", label="recvmsg() + HTTP/3 with QUIC VReverso")
    ax.fill_between(times, util4_int_low, util4_int_up, color="cyan", alpha=.2)

    plt.xlabel('Time (s)', fontsize=20)
    plt.ylabel('Average CPU Utilization (%)', fontsize=20)
    plt.grid(True)
    plt.legend(fontsize=20)
    plt.tight_layout()
    plt.savefig("cpudl_1gbps.pdf")

def get_file_paths(directory):
    return [os.path.join(directory, file) for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]

cpu_frequency = 2.8 * 10**9 # Replace with your frequency.

directory = "1_measure_quicv1"  # Replace with the path to your directory
directory_2 = "3_measure_quicv0079_1097"
directory_3 = "measure_quicv1_recvmsg"
directory_4 = "measure_quicv0079_1097_recvmsg"

file_paths = get_file_paths(directory)
file_paths_2 = get_file_paths(directory_2)
file_paths_3 = get_file_paths(directory_3)
file_paths_4 = get_file_paths(directory_4)

data = process_files(file_paths, cpu_frequency)
data2 = process_files(file_paths_2, cpu_frequency)
data3 = process_files(file_paths_3, cpu_frequency)
data4 = process_files(file_paths_4, cpu_frequency)
avg_data, conf_int = calculate_mean_confidence_interval(data)
avg_data_2, conf_int_2 = calculate_mean_confidence_interval(data2)
avg_data_3, conf_int_3 = calculate_mean_confidence_interval(data3)
avg_data_4, conf_int_4 = calculate_mean_confidence_interval(data4)
plot_utilization(avg_data, avg_data_2, avg_data_3, avg_data_4, conf_int, conf_int_2, conf_int_3, conf_int_4)
```

Change the name of the 4 directories in the script according to the chosen ones for
the 4 runs of `measure_dl_i71165.sh`.

