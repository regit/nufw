#!/bin/sh

echo "[+] Run libtoolize"
libtoolize --force --automake || exit $?

#-----------------------------------------------------------------------------

find_tool_version()
{
    TOOL=$1
    MINVER=$2
    OKVER=$3
    NOKREG=$4

    for i in ${OKVER}; do
        if ${TOOL}${i} --version > /dev/null 2>&1; then
            echo "${TOOL}${i}"
            exit
        fi
    done
    if ${TOOL} --version > /dev/null 2>&1; then
        case "$(${TOOL} --version | sed -e '1s/[^0-9]*//' -e q)" in
            ${NOKREG})
            echo "You need ${TOOL} version (at least) ${MINVER} !" 1>&2
            exit 1;;
        esac
    else
        echo "You need ${TOOL} !" 1>&2
        exit 1
    fi
    echo "${TOOL}"
}

#-----------------------------------------------------------------------------

AUTOMAKE_MIN_VERSION="1.8"
AUTOMAKE_OK_VERSIONS="-1.9 19 -1.8 18"
AUTOMAKE_NOK_REGEXP='0|0.*|1|1.[0-7]*'

AUTOCONF_MIN_VERSION="2.58"
AUTOCONF_OK_VERSIONS="258 259"
AUTOCONF_NOK_REGEXP='0|0.*|1|1.*|2|2.[0-4]*|2.5[0-7]*'

AUTOMAKE=$(find_tool_version automake "${AUTOMAKE_MIN_VERSION}" \
                                      "${AUTOMAKE_OK_VERSIONS}" \
                                      "${AUTOMAKE_NOK_REGEXP}") || exit 1
ACLOCAL=$(find_tool_version aclocal "${AUTOMAKE_MIN_VERSION}" \
                                    "${AUTOMAKE_OK_VERSIONS}" \
                                    "${AUTOMAKE_NOK_REGEXP}") || exit 1
AUTOCONF=$(find_tool_version autoconf "${AUTOCONF_MIN_VERSION}" \
                                      "${AUTOCONF_OK_VERSIONS}" \
                                      "${AUTOCONF_NOK_REGEXP}") || exit 1
AUTOHEADER=$(find_tool_version autoheader "${AUTOCONF_MIN_VERSION}" \
                                          "${AUTOCONF_OK_VERSIONS}" \
                                          "${AUTOCONF_NOK_REGEXP}") || exit 1

#-----------------------------------------------------------------------------

echo "[+] Run aclocal"
$ACLOCAL || exit $?

echo "[+] Run autoheader"
$AUTOHEADER || exit $?

echo "[+] Run autoconf"
$AUTOCONF || exit $?

echo "[+] Run automake"
$AUTOMAKE --add-missing --copy -Wno-portability || exit $?

echo
echo "Now type: ./configure"
echo "Help with: ./configure --help"

