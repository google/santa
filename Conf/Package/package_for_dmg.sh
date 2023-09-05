!#/bin/sh
# Script to generate a release DMG locally

WORKSPACE_DIR=$(bazel info | grep 'workspace:' | awk '{print $2}')

BASEPATH=$(basename $0)
TIMESTAMP=$(date +%Y%m%d%H%M%S)
TMP_DIR=$(mktemp -dt "$BASEPATH.$TIMESTAMP.$$")/


# 1.Build a release tarball with bazel build --apple_generate_dsym -c opt //:release
bazel build --apple_generate_dsym -c opt //:release

# 2. Extract the resulting tarball into a directory and export the path to this
# dir with export RELEASE_ROOT=/path/to/dir
cp bazel-bin/santa-release.tar.gz $TMP_DIR/
cd $TMP_DIR
tar zxf ./santa-release.tar.gz
export RELEASE_ROOT=$TMP_DIR

# 3. Export shell variables SIGNING_IDENTITY, SIGNING_TEAMID and SIGNING_KEYCHAIN
# specifying the identity, team ID and path to the keychain file containing
# your Apple-provided signing ID.

export SIGNING_IDENTITY=""
export SIGNING_TEAMID=""
export SIGNING_KEYCHAIN=""

# 4. Export shell variables INSTALLER_SIGNING_IDENTITY and
#    INSTALLER_SIGNING_KEYCHAIN, similar to the ones in step 3 but for the
#    Developer ID Installer certificate for signing the .pkg file.
export INSTALLER_SIGNING_IDENTITY=""
export INSTALLER_SIGNING_KEYCHAIN=""

# 5. Export the shell variable NOTARIZATION_TOOL that handles notarizing various
#    files as part of the packaging process. This is to allow you to intercept and
#    manage the notarization process but if you just want to use the built-in Xcode
#    tools we provide notarization_tool.sh to handle this; it requires you to set
#    NOTARIZATION_USERNAME and NOTARIZATION_PASSWORD environment variables
#    containing the Apple ID login info of the user you'll be notarizing as.
NOTARIZATION_USERNAME=""
NOTARIZATION_PASSWORD=""
/usr/bin/xcrun notarytool submit "${2}" --wait \
  --apple-id "${NOTARIZATION_USERNAME}" --password "${NOTARIZATION_PASSWORD}"



# 6. Export the shell variable ARTIFACTS_DIR specifying the dir to store the
#    output files in.
export ARTIFACTS_DIR=""

# 7. Execute the package_and_sign.sh script. Once complete the folder specified
#    in ARTIFACTS_DIR will contain the DMG file and an updated release tarball
#    with signed and notarized versions of all the built components.
package_and_sign.sh
