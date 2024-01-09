MIN=2200MHz
MAX=4300MHz
SET_MIN=2200MHz
SET_MAX=2200MHz
BENCH=$1
PROFILE=$2

sudo cpupower frequency-set -d $SET_MIN -u $SET_MAX -g performance
taskset -c 0 cargo bench --bench $BENCH --profile $PROFILE
sudo cpupower frequency-set -d $MIN -u $MAX -g schedutil


