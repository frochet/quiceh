MIN=800MHz
MAX=3200MHz
SET_MIN=2000MHz
SET_MAX=2000MHz
BENCH=$1
PROFILE=$2

sudo cpupower -c 0 frequency-set -d $SET_MIN -u $SET_MAX -g performance
taskset -c 0 cargo bench --bench $BENCH --profile $PROFILE
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave


