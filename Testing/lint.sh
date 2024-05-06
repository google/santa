#!/bin/bash
set -exo pipefail

GIT_ROOT=$(git rev-parse --show-toplevel)

find $GIT_ROOT \( -name "*.m" -o -name "*.h" -o -name "*.mm" -o -name "*.cc" \) -exec clang-format --Werror --dry-run {} \+

! git grep -EIn $'[ \t]+$' -- ':(exclude)*.patch'

go install github.com/bazelbuild/buildtools/buildifier@latest
~/go/bin/buildifier --lint=warn -r $GIT_ROOT

python3 -m pip install -q pylint
find $GIT_ROOT \( -name "*.py" \) -exec python3 -m pylint --score n --rcfile=$GIT_ROOT/.pylintrc {} \+
