#!/bin/bash

# This script signs all of Santa's components, verifies the signatures,
# notarizes all of the components, staples them, packages them up, signs the
# package, notarizes the package, puts the package in a DMG and notarizes the
# DMG. It also outputs a single release tarball.
# All of the following environment variables are required.

# RELEASE_ROOT is a required environment variable that points to the root
# of an extracted release tarball produced with the :release and :release_driver
# rules in Santa's main BUILD file.
[[ -n "${RELEASE_ROOT}" ]] || die "RELEASE_ROOT unset"

# SIGNING_IDENTITY, SIGNING_TEAMID and SIGNING_KEYCHAIN are required environment
# variables specifying the identity and keychain to pass to the codesign tool
# and the team ID to use for verification.
[[ -n "${SIGNING_IDENTITY}" ]] || die "SIGNING_IDENTITY unset"
[[ -n "${SIGNING_TEAMID}" ]] || die "SIGNING_TEAMID unset"
[[ -n "${SIGNING_KEYCHAIN}" ]] || die "SIGNING_KEYCHAIN unset"

# INSTALLER_SIGNING_IDENTITY and INSTALLER_SIGNING_KEYCHAIN are required
# environment variables specifying the identity and keychain to use when signing
# the distribution package.
[[ -n "${INSTALLER_SIGNING_IDENTITY}" ]] || die "INSTALLER_SIGNING_IDENTITY unset"
[[ -n "${INSTALLER_SIGNING_KEYCHAIN}" ]] || die "INSTALLER_SIGNING_KEYCHAIN unset"

# NOTARIZATION_TOOL is a required environment variable pointing to a wrapper
# tool around the tool to use for notarization. The tool must take 2 flags:
#    --file
#        - pointing at a zip file containing the artifact to notarize
#    --primary-bundle-id
#        - specifying the CFBundleID of the artifact being notarized
[[ -n "${NOTARIZATION_TOOL}" ]] || die "NOTARIZATION_TOOL unset"

# ARTIFACTS_DIR is a required environment variable pointing at a directory to
# place the output artifacts in.
[[ -n "${ARTIFACTS_DIR}" ]] || die "ARTIFACTS_DIR unset"

################################################################################

function die {
  echo "${@}"
  exit 2
}

readonly INPUT_APP="${RELEASE_ROOT}/binaries/Santa.app"
readonly INPUT_SYSX="${INPUT_APP}/Contents/Library/SystemExtensions/com.google.santa.daemon.systemextension"
readonly INPUT_SANTACTL="${INPUT_APP}/Contents/MacOS/santactl"
readonly INPUT_SANTABS="${INPUT_APP}/Contents/MacOS/santabundleservice"
readonly INPUT_SANTAMS="${INPUT_APP}/Contents/MacOS/santametricservice"

readonly RELEASE_NAME="santa-$(/usr/bin/defaults read "${INPUT_APP}/Contents/Info.plist" CFBundleShortVersionString)"

readonly SCRATCH=$(/usr/bin/mktemp -d "${TMPDIR}/santa-"XXXXXX)
readonly APP_PKG_ROOT="${SCRATCH}/app_pkg_root"
readonly APP_PKG_SCRIPTS="${SCRATCH}/pkg_scripts"
readonly ENTITLEMENTS="${SCRATCH}/entitlements"

readonly SCRIPT_PATH="$(/usr/bin/dirname -- ${BASH_SOURCE[0]})"

/bin/mkdir -p "${APP_PKG_ROOT}" "${APP_PKG_SCRIPTS}" "${ENTITLEMENTS}"

readonly DMG_PATH="${ARTIFACTS_DIR}/${RELEASE_NAME}.dmg"
readonly TAR_PATH="${ARTIFACTS_DIR}/${RELEASE_NAME}.tar.gz"

# Sign all of binaries/bundles. Maintain inside-out ordering where necessary
for ARTIFACT in "${INPUT_SANTACTL}" "${INPUT_SANTABS}" "${INPUT_SANTAMS}" "${INPUT_SYSX}" "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")
  EN="${ENTITLEMENTS}/${BN}.entitlements"

  echo "extracting ${BN} entitlements"
  /usr/bin/codesign -d --entitlements "${EN}" "${ARTIFACT}"
  if [[ -s "${EN}" ]]; then
    EN="--entitlements ${EN}"
  else
    EN=""
  fi

  echo "codesigning ${BN}"
  /usr/bin/codesign --sign "${SIGNING_IDENTITY}" --keychain "${SIGNING_KEYCHAIN}" \
        ${EN} --timestamp --force --generate-entitlement-der \
        --options library,kill,runtime "${ARTIFACT}"
done

# Notarize all the bundles
for ARTIFACT in "${INPUT_SYSX}" "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")

  echo "zipping ${BN}"
  /usr/bin/zip -9r "${SCRATCH}/${BN}.zip" "${ARTIFACT}"

  echo "notarizing ${BN}"
  PBID=$(/usr/bin/defaults read "${ARTIFACT}/Contents/Info.plist" CFBundleIdentifier)
  "${NOTARIZATION_TOOL}" --file "${SCRATCH}/${BN}.zip" --primary-bundle-id "${PBID}"
done

# Staple the App.
for ARTIFACT in "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")

  echo "stapling ${BN}"
  /usr/bin/xcrun stapler staple "${ARTIFACT}"
done

# Ensure _CodeSignature/CodeResources files have 0644 permissions so they can
# be verified without using sudo.
/usr/bin/find "${RELEASE_ROOT}/binaries" -type f -name CodeResources -exec chmod 0644 {} \;
/usr/bin/find "${RELEASE_ROOT}/binaries" -type d -exec chmod 0755 {} \;
/usr/bin/find "${RELEASE_ROOT}/conf" -type f -name "com.google.santa*" -exec chmod 0644 {} \;

echo "verifying signatures"
/usr/bin/codesign -vv -R="certificate leaf[subject.OU] = ${SIGNING_TEAMID}" \
  "${RELEASE_ROOT}/binaries/"* || die "bad signature"

echo "creating fresh release tarball"
/bin/mkdir -p "${RELEASE_ROOT}/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/binaries" "${RELEASE_ROOT}/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/conf" "${RELEASE_ROOT}/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/dsym" "${RELEASE_ROOT}/${RELEASE_NAME}"
/usr/bin/tar -C "${RELEASE_ROOT}" -czvf "${TAR_PATH}" "${RELEASE_NAME}" || die "failed to create release tarball"

echo "creating app pkg"
/bin/mkdir -p "${APP_PKG_ROOT}/Applications" \
  "${APP_PKG_ROOT}/Library/LaunchAgents" \
  "${APP_PKG_ROOT}/Library/LaunchDaemons" \
  "${APP_PKG_ROOT}/private/etc/asl" \
  "${APP_PKG_ROOT}/private/etc/newsyslog.d"
/bin/cp -vXR "${RELEASE_ROOT}/binaries/Santa.app" "${APP_PKG_ROOT}/Applications/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santad.plist" "${APP_PKG_ROOT}/Library/LaunchDaemons/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santa.plist" "${APP_PKG_ROOT}/Library/LaunchAgents/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santa.bundleservice.plist" "${APP_PKG_ROOT}/Library/LaunchDaemons/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santa.metricservice.plist" "${APP_PKG_ROOT}/Library/LaunchDaemons/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santa.asl.conf" "${APP_PKG_ROOT}/private/etc/asl/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.google.santa.newsyslog.conf" "${APP_PKG_ROOT}/private/etc/newsyslog.d/"
/bin/cp -vXL "${SCRIPT_PATH}/preinstall" "${APP_PKG_SCRIPTS}/"
/bin/cp -vXL "${SCRIPT_PATH}/postinstall" "${APP_PKG_SCRIPTS}/"
/bin/chmod +x "${APP_PKG_SCRIPTS}/"*

# Disable bundle relocation.
/usr/bin/pkgbuild --analyze --root "${APP_PKG_ROOT}" "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsRelocatable -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsVersionChecked -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleOverwriteAction -string upgrade "${SCRATCH}/component.plist"
/usr/bin/plutil -replace ChildBundles -json "[]" "${SCRATCH}/component.plist"

# Build app package
/usr/bin/pkgbuild --identifier "com.google.santa" \
  --version "$(echo "${RELEASE_NAME}" | cut -d - -f2)" \
  --root "${APP_PKG_ROOT}" \
  --component-plist "${SCRATCH}/component.plist" \
  --scripts "${APP_PKG_SCRIPTS}" \
  "${SCRATCH}/app.pkg"

# Build signed distribution package
echo "productbuild pkg"
/bin/mkdir -p "${SCRATCH}/${RELEASE_NAME}"
/usr/bin/productbuild \
  --distribution "${SCRIPT_PATH}/Distribution.xml" \
  --package-path "${SCRATCH}" \
  --sign "${INSTALLER_SIGNING_IDENTITY}" --keychain "${INSTALLER_SIGNING_KEYCHAIN}" \
  "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg"

echo "verifying pkg signature"
/usr/sbin/pkgutil --check-signature "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" || die "bad pkg signature"

echo "notarizing pkg"
"${NOTARIZATION_TOOL}" --file "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" \
    --primary-bundle-id "com.google.santa"

echo "stapling pkg"
/usr/bin/xcrun stapler staple "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" || die "failed to staple pkg"

echo "wrapping pkg in dmg"
/usr/bin/hdiutil create -fs HFS+ -format UDZO \
    -volname "${RELEASE_NAME}" \
    -ov -imagekey zlib-level=9 \
    -srcfolder "${SCRATCH}/${RELEASE_NAME}/" "${DMG_PATH}" || die "failed to wrap pkg in dmg"

echo "notarizing dmg"
"${NOTARIZATION_TOOL}" --file "${DMG_PATH}" --primary-bundle-id "com.google.santa"

echo "stapling dmg"
/usr/bin/xcrun stapler staple "${DMG_PATH}" || die "failed to staple dmg"
