MIN=400MHz
MAX=4700MHz
SET_MIN=2799MHz
SET_MAX=2800MHz
BENCH=$1
PROFILE=$2

sudo cpupower frequency-set -d $SET_MIN -u $SET_MAX -g performance
taskset -c 0 cargo bench --bench $BENCH --profile $PROFILE
sudo cpupower frequency-set -d $MIN -u $MAX -g powersave


