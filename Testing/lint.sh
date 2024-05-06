#!/bin/bash
set -exo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

find ${GIT_ROOT} \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec clang-format --Werror --dry-run {} \+

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

go install github.com/bazelbuild/buildtools/buildifier@latest
~/go/bin/buildifier --lint=warn -r ${GIT_ROOT}

python3 -m pip install -q pyink
python3 -m pyink --config ${GIT_ROOT}/.pyink-config --check ${GIT_ROOT}
