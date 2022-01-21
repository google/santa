GIT_ROOT=$(git rev-parse --show-toplevel)
ANALYZE_PATH="$GIT_ROOT/Testing/clang_analyzer"
TITLE="Santa Clang Analysis"

EXECUTION_ROOT=`bazel info execution_root`

function main() {
    bazel clean
    bazel run @hedron_compile_commands//:refresh_all

    analyze-build --cdb $GIT_ROOT/compile_commands.json -o $ANALYZE_PATH/analysis --html-title "$TITLE" --use-analyzer=$(which clang)
}

main $@
exit $?
