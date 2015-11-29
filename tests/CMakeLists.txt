enable_testing()

set(SRC_DIR "../src")

add_executable("parse_config" "${SRC_DIR}/config.c" "parse_config.c")
add_test("parse_config" "parse_config")
