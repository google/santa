#!/bin/sh
#
# Test script to automate copying and installing Santa in a VM.
set -e

# Clean up previous runs
echo "Running \"sudo rm -f /Users/peterm/rules.json\""
ssh -t peterm@192.168.65.2 "sudo rm -f /Users/peterm/rules.json"
ssh peterm@192.168.65.2 "rm -f /Users/peterm/santa-release.tar.gz"
# Delete the rule blocking /bin/ls
#ssh peterm
ssh -t peterm@192.168.65.2 "sudo santactl rule --remove --identifier 84de9c61777ca36b13228e2446d53e966096e78db7a72c632b5c185b2ffe68a6"

# Copy and install Santa
scp ./bazel-bin/santa-release.tar.gz peterm@192.168.65.2:
ssh  peterm@192.168.65.2 "tar zxvf ./santa-release.tar.gz"
ssh -t peterm@192.168.65.2 "cd ./conf && sudo ./install.sh"

# Now export rules
ssh -t peterm@192.168.65.2 "sudo santactl rules --export /Users/peterm/rules.json"
# Cat the file
ssh peterm@192.168.65.2 "cat /Users/peterm/rules.json"

# Edit the file to have the hash for /bin/ls

# Import the new rules file
