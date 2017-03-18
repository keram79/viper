#!/bin/bash

python3 viper-api -p 18080 &
server_pid=$!
sleep 2

pyresttest http://localhost:18080 tests/pyresttest_viper_api.yml
test_result=$?
kill ${server_pid}

exit ${test_result}
