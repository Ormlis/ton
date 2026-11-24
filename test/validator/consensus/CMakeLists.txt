add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus PRIVATE
    adnl
    adnltest
    dht
    overlay
    tdactor
    tdutils
    tl_api
    ton_validator
    validator
)

add_executable(test-consensus-metrics
    test-candidate-resolver-metrics.cpp
    test-consensus-metrics.cpp
)
target_link_libraries(test-consensus-metrics PRIVATE
    adnl
    dht
    metrics
    overlay
    tdactor
    tdutils
    td-test-main
    tl_api
    ton_validator
    validator
)
ton_test(test-consensus-metrics)

add_executable(test-shard-groups test-shard-groups.cpp)
target_link_libraries(test-shard-groups PRIVATE td-test-main tdactor tdutils tl_api adnl overlay validator ton_validator)
ton_test(test-shard-groups)
