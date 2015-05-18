#
#  Package Makefile for Santa
#  Requires TheLuggage (github.com/unixorn/luggage) to be installed
#
#  Will generate a package based on the latest release. You can replace
#  the PACKAGE_VERSION variable with a specific variable instead if you wish.
#

LUGGAGE:=/usr/local/share/luggage/luggage.make
include ${LUGGAGE}

TITLE:=santa
REVERSE_DOMAIN:=com.google

# Get latest Release version using the GitHub API. Each release is bound to a
# git tag, which should always be a semantic version number
PACKAGE_VERSION:=$(shell curl -fs https://api.github.com/repos/google/santa/releases |\
	python -c 'import json, sys; print json.load(sys.stdin)[0]["tag_name"]' 2>/dev/null)

# Get the download URL for the latest Release using the GitHub API. Each release
# should have a single 'asset' which will be a tar.bz2 containing all of the files
# associated with that release.
# The tarball layout is:
#
#   santa-$version.tar.bz2
#   +--santa-$version
#         |-- binaries
#         |      |-- santa-driver.kext
#         |      |-- Santa.app
#         |      |-- santad
#         |      +-- santactl
#         |-- conf
#         |    |-- install.sh
#         |    |-- com.google.santad.plist
#         |    |-- com.google.santasync.plist
#         |    |-- com.google.santagui.plist
#         |    +-- com.google.santa.asl.conf
#         +--dsym
#             |-- santa-driver.kext.dSYM
#             |-- Santa.app.dSYM
#             |-- santad.dSYM
#             +-- santactl.dSYM
#
PACKAGE_DOWNLOAD_URL:=$(shell curl -fs https://api.github.com/repos/google/santa/releases |\
	python -c 'import json, sys; print json.load(sys.stdin)[0]["assets"][0]["browser_download_url"]' 2>/dev/null)

PAYLOAD:=pack-usr-libexec-santad \
	pack-usr-sbin-santactl \
	pack-Library-Extensions-santa-driver.kext \
	pack-applications-Santa.app \
	pack-Library-LaunchDaemons-com.google.santad.plist \
	pack-Library-LaunchDaemons-com.google.santasync.plist \
	pack-Library-LaunchAgents-com.google.santagui.plist \
	pack-etc-asl-com.google.santa.asl.conf \
	pack-script-preinstall \
	pack-script-postinstall

santad: download
santactl: download
santa-driver.kext: download
Santa.app: download
com.google.santad.plist: download
com.google.santagui.plist: download
com.google.santasync.plist: download
com.google.santa.asl.conf: download

download:
	$(if $(PACKAGE_VERSION),, $(error GitHub API returned unexpected result. Wait a while and try again))
	$(if $(PACKAGE_DOWNLOAD_URL),, $(error GitHub API returned unexpected result. Wait a while and try again))

	@curl -fL ${PACKAGE_DOWNLOAD_URL} | tar xvj --strip=2
	@rm -rf *.dSYM

pack-usr-libexec-santad: santad l_usr
	@sudo mkdir -p ${WORK_D}/usr/libexec
	@sudo chown root:wheel ${WORK_D}/usr/libexec
	@sudo chmod 755 ${WORK_D}/usr/libexec
	@sudo install -m 755 -o root -g wheel santad ${WORK_D}/usr/libexec

pack-etc-asl-com.google.santa.asl.conf: com.google.santa.asl.conf l_private_etc
	@sudo mkdir -p ${WORK_D}/private/etc/asl
	@sudo chown root:wheel ${WORK_D}/private/etc/asl
	@sudo chmod 755 ${WORK_D}/private/etc/asl
	@sudo install -m 644 -o root -g wheel com.google.santa.asl.conf ${WORK_D}/private/etc/asl

pack-Library-Extensions-santa-driver.kext: santa-driver.kext l_Library
	@sudo mkdir -p ${WORK_D}/Library/Extensions
	@sudo ${DITTO} --noqtn santa-driver.kext ${WORK_D}/Library/Extensions/santa-driver.kext
	@sudo chown -R root:wheel ${WORK_D}/Library/Extensions/santa-driver.kext
	@sudo chmod -R 755 ${WORK_D}/Library/Extensions/santa-driver.kext

clean: myclean

myclean:
	@rm -rf *.dSYM
	@rm -rf Santa.app
	@rm -rf santa-driver.kext
	@rm -f santad
	@rm -f santactl
	@rm -f config.plist
	@rm -f com.google.santa.asl.conf
	@rm -f com.google.santad.plist
	@rm -f com.google.santagui.plist
	@rm -f com.google.santasync.plist
	@rm -f install.sh
