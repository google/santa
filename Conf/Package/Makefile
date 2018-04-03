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
# git tag, which should always be a semantic version number. The most recent
# release is always first in the API result.
PACKAGE_VERSION:=$(shell curl -fs https://api.github.com/repos/google/santa/releases |\
	python -c 'import json, sys; print json.load(sys.stdin)[0]["tag_name"]' 2>/dev/null)

# Get the download URL for the latest Release. Each release should have a
# tarball named santa-$version.tar.bz2 containing all of the files associated
# with that release. The tarball layout is:
#
#   santa-$version.tar.bz2
#   +--santa-$version
#         |-- binaries
#         |    |-- santa-driver.kext
#         |    |-- Santa.app
#         |-- conf
#         |    |-- install.sh
#         |    |-- com.google.santad.plist
#         |    |-- com.google.santagui.plist
#         |    +-- com.google.santa.asl.conf
#         |    +-- com.google.santa.newsyslog.conf
#         +--dsym
#              |-- santa-driver.kext.dSYM
#              |-- Santa.app.dSYM
#              |-- santad.dSYM
#              +-- santactl.dSYM
PACKAGE_DOWNLOAD_URL:="https://github.com/google/santa/releases/download/${PACKAGE_VERSION}/santa-${PACKAGE_VERSION}.tar.bz2"

PAYLOAD:=pack-Library-Extensions-santa-driver.kext \
	pack-applications-Santa.app \
	pack-Library-LaunchDaemons-com.google.santad.plist \
	pack-Library-LaunchAgents-com.google.santagui.plist \
	pack-etc-asl-com.google.santa.asl.conf \
	pack-etc-newsyslog.d-com.google.santa.newsyslog.conf \
	pack-script-preinstall \
	pack-script-postinstall

santa-driver.kext: download
Santa.app: download
com.google.santad.plist: download
com.google.santagui.plist: download
com.google.santa.asl.conf: download
com.google.santa.newsyslog.conf: download

download:
	$(if $(PACKAGE_VERSION),, $(error GitHub API returned unexpected result. Wait a while and try again))

	@curl -fL ${PACKAGE_DOWNLOAD_URL} | tar xvj --strip=2
	@rm -rf *.dSYM

pack-etc-asl-com.google.santa.asl.conf: com.google.santa.asl.conf l_private_etc
	@sudo mkdir -p ${WORK_D}/private/etc/asl
	@sudo chown root:wheel ${WORK_D}/private/etc/asl
	@sudo chmod 755 ${WORK_D}/private/etc/asl
	@sudo install -m 644 -o root -g wheel com.google.santa.asl.conf ${WORK_D}/private/etc/asl

pack-etc-newsyslog.d-com.google.santa.newsyslog.conf: com.google.santa.newsyslog.conf l_private_etc
	@sudo mkdir -p ${WORK_D}/private/etc/newsyslog.d
	@sudo chown root:wheel ${WORK_D}/private/etc/newsyslog.d
	@sudo chmod 755 ${WORK_D}/private/etc/newsyslog.d
	@sudo install -m 644 -o root -g wheel com.google.santa.newsyslog.conf ${WORK_D}/private/etc/newsyslog.d

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
	@rm -f config.plist
	@rm -f com.google.santa.asl.conf
	@rm -f com.google.santa.newsyslog.conf
	@rm -f com.google.santad.plist
	@rm -f com.google.santagui.plist
	@rm -f install.sh
	@rm -f uninstall.sh
