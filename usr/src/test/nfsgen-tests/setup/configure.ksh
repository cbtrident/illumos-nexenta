#! /usr/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

DIR=$(dirname $0)
NAME=$(basename $0)

. ${STF_SUITE}/include/nfsgen.kshlib

# Turn on debug info, if requested
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG:$NFSGEN_DEBUG
[[ :$NFSGEN_DEBUG: = *:${NAME}:* || :${NFSGEN_DEBUG}: = *:all:* ]] \
       && set -x 

RUN_CHECK mkdir -p -m 0777 $STF_TMPDIR || exit $STF_UNINITIATED

# Check if needed binaries exist on CLIENT2 if CLIENT2 is set
if [[ -n $CLIENT2 ]]; then
	CLIENT2_ARCH=""
	CLIENT2_BIN=$STF_SUITE/bin/$CLIENT2_ARCH/chg_usr_exec
	if RSH root $CLIENT2 "[[ -x $CLIENT2_BIN ]]"; then
		CLIENT2_BIN_USED=1
	elif [[ -x $CLIENT2_BIN ]]; then
		CLIENT2_BIN_USED=0
	else
		echo "$NAME: failed to find binary($CLIENT2_BIN) on both $CLIENT2 and local host"
		exit $STF_UNINITIATED
	fi
fi

if [[ $SETUP == "none" ]]; then
	echo " SETUP=<$SETUP>"
	echo " Use existing setup, check it ..."
	RUN_CHECK mount -p > $MNTDIR/testfile 2>&1 || exit $STF_UNINITIATED

	# Get SERVER and UID01,  save them in config file
	realMNT=$(get_realMNT $MNTDIR 2> $MNTDIR/testfile2)
	(( $? != 0 )) && cat $MNTDIR/testfile* && exit $STF_UNINITIATED
	ZNAME=$(zonename)
	SERVER=$(grep " $realMNT" $MNTDIR/testfile | cut -d: -f1)
	SHRDIR=$(grep " $realMNT" $MNTDIR/testfile | cut -d\  -f1 | cut -d: -f2)
	[[ $SHRDIR != "/" ]] && SHRDIR="${SHRDIR%%/}"
	MNTOPT=$(grep " $realMNT" $MNTDIR/testfile | cut -d\  -f7)
	MNTOPT=$(echo $MNTOPT | sed -e "s/nodevices,*//" \
		-e "s/zone=${ZNAME},*//" -e "s/,$//" -e "s/^,//")
	TGID=$(getent group $TGROUP | awk 'BEGIN {FS=":"} {print $3}')
	TUID01=$(getent passwd $TUSER01 | awk 'BEGIN {FS=":"} {print $3}')
	TUID02=$(getent passwd $TUSER02 | awk 'BEGIN {FS=":"} {print $3}')

	is_IPv6 $SERVER > $STF_TMPDIR/is_IPv6.$$ 2>&1
	IS_IPV6=$?
	# by default, we assume it's ipv4
	[[ $IS_IPV6 != 1 ]] && IS_IPV6=0

	RUN_CHECK rm $MNTDIR/testfile* || exit $STF_UNINITIATED

	nfsstat -m $realMNT | grep Flags: | grep "sec=krb5" > /dev/null 2>&1
	(( $? == 0 )) && export IS_KRB5=1 || export IS_KRB5=0

	cat >> $1 <<-EOF
export realMNT="$realMNT"
export SERVER="$SERVER"
export SHRDIR="$SHRDIR"
export MNTDIR="${MNTDIR%%/}"
export MNTOPT="$MNTOPT"
export TGID="$TGID"
export TUID01="$TUID01"
export TUID02="$TUID02"
export TESTVERS="$TESTVERS"
export TestZFS="$TestZFS"
export IS_KRB5="$IS_KRB5"
export IS_IPV6=$IS_IPV6
export CLIENT2_ARCH=$CLIENT2_ARCH
export CLIENT2_BIN_USED=$CLIENT2_BIN_USED
EOF

	exit $STF_PASS
fi

# Verify the valid SETUP value
if [[ ! -d ${STF_SUITE}/bin/$SETUP ]]; then
	echo "$NAME: SETUP=<$SETUP> is not supported."
	echo "\tPlease redefine the valid SETUP value: {nfsv4, none}"
	exit $STF_UNSUPPORTED
fi

# Check if needed binaries exist on the server or local host
SERVER_ARCH=""
SERVER_BIN=$STF_SUITE/bin/$SERVER_ARCH/chg_usr_exec
if RSH root $SERVER "[[ -x $SERVER_BIN ]]"; then
	SERVER_BIN_USED=1
elif [[ -x $SERVER_BIN ]]; then
	SERVER_BIN_USED=0
else
	echo "$NAME: failed to find binary($SERVER_BIN) on both $SERVER and local host"
	exit $STF_FAIL
fi


# Verify "anon=0" is in share options
if [[ -n $SHROPT ]]; then
	echo "$SHROPT" | grep "anon" > /dev/null
	(( $? != 0 )) && SHROPT="$SHROPT,anon=0" || SHROPT=$SHROPT
else
	SHROPT="anon=0"
fi
export SHROPT

# get dns server from the following sources
#	- user specifid value
#	- /etc/resolv.conf
#	- default("129.145.155.226")
if [[ -z $DNS_SERVER && -f /etc/resolv.conf ]]; then
        dns_server=$(grep nameserver /etc/resolv.conf | head -1 | \
            awk '{print $2}')
        [[ -n $dns_server  ]] && DNS_SERVER=$dns_server
fi
DNS_SERVER=${DNS_SERVER:-129.145.155.226}

# check if we need to test krb5
echo $SHROPT | grep "sec=krb5" > /dev/null 2>&1
(( $? == 0 )) && export IS_KRB5=1 || export IS_KRB5=0

# Check TX related info
RUN_CHECK check_for_cipso $SHRDIR $MNTDIR $MNTOPT || return $STF_UNSUPPORTED

# Get free GID and create a group
TGID=$(get_free_gid $SERVER)
(( $? != 0 )) && echo "$NAME: Can't get a unused gid for $TUSER01" \
        && exit $STF_UNINITIATED
groupdel $TGROUP >/dev/null 2>&1
RUN_CHECK groupadd -g $TGID $TGROUP || exit $STF_UNINITIATED

# Get free UID and create users.
TUID01=$(get_free_uid $SERVER)
(( $? != 0 )) && echo "$NAME: Can't get a unused uid for $TUSER01" \
	&& exit $STF_UNINITIATED
userdel $TUSER01 >/dev/null 2>&1
RUN_CHECK useradd -u $TUID01 -g $TGROUP -d /tmp $TUSER01 \
	|| exit $STF_UNINITIATED
TUID02=$(get_free_uid $SERVER)
(( $? != 0 )) && echo "$NAME: Can't get a unused uid for $TUSER02" \
	&& exit $STF_UNINITIATED
userdel $TUSER02 >/dev/null 2>&1
RUN_CHECK useradd -u $TUID02 -g $TGROUP -d /tmp $TUSER02 \
	|| exit $STF_UNINITIATED

# Check if it's ipv6 config.
is_IPv6 $SERVER > $STF_TMPDIR/is_IPv6.$$ 2>&1
IS_IPV6=$?
# by default, we assume it's ipv4
[[ $IS_IPV6 != 1 ]] && IS_IPV6=0

[[ $SHRDIR != "/" ]] && SHRDIR="${SHRDIR%%/}"
# Save it in config file
cat >> $1 <<-EOF
export SHRDIR=$SHRDIR
export MNTDIR="${MNTDIR%%/}"
export TUID01=$TUID01
export TUID02=$TUID02
export TGID=$TGID
export IS_KRB5=$IS_KRB5
export IS_IPV6=$IS_IPV6
export DNS_SERVER=$DNS_SERVER
export SERVER_ARCH=$SERVER_ARCH
export SERVER_BIN_USED=$SERVER_BIN_USED
export CLIENT2_ARCH=$CLIENT2_ARCH
export CLIENT2_BIN_USED=$CLIENT2_BIN_USED
EOF

#
# General client side setup
#    - creating test user
#    - setting up mapid domain
#

# Set mapid domain on client
RUN_CHECK set_nfs_property NFSMAPID_DOMAIN $NFSMAPID_DOMAIN \
    $STF_TMPDIR/mapid_backup || exit $STF_UNINITIATED

#
# General server side setup
#    - creating test user
#    - setting up mapid domain
#

# Create temp dir on server
RUN_CHECK RSH root $SERVER "mkdir -p -m 0777 $SRV_TMPDIR" \
    || exit $STF_UNINITIATED

# Setup kerberos if needed.
if [[ $IS_KRB5 == 1 ]]; then
	print "Checking krb5 setup ..."
	RUN_CHECK krb5_config -s || exit $STF_UNINITIATED
	# check and reset MNTOPT to match the SHROPT
	SecOPT=$(echo $SHROPT | \
	    nawk -F\, '{for (i=1; i<=NF; i++) {if ($i ~ /sec=/) print $i} }')
	SecOPT=$(echo $SecOPT | nawk -F\: '{print $1}')
	echo $MNTOPT | grep "sec=krb5" > /dev/null 2>&1
	if (( $? == 0 )); then
		MntOPT=$(echo $MNTOPT | \
	    	    nawk -F\, \
			'{for (i=1; i<=NF; i++) {if ($i ~ /sec=/) print $i} }')
		MntOPT=$(echo $MntOPT | nawk -F\: '{print $1}')
		if [[ $MntOPT != $SecOPT ]]; then
			print "user defined unmatched sec= for share and mount"
			print "    SHROPT=<$SHROPT>, MNTOPT=$<$MNTOPT>"
			print "Reset MNTOPT to use same sec= option as share"
			export MNTOPT=$(echo $MNTOPT | sed "s/$MntOPT/$SecOPT/")
			echo "export MNTOPT=$MNTOPT" >> $1
		fi
	fi
	echo "export SecOPT=$SecOPT" >> $1
fi

# Copy files
cat > $STF_TMPDIR/srv_env.vars << EOF
export SHRDIR=$SHRDIR
export MNTDIR="${MNTDIR%%/}"
export NFSMAPID_DOMAIN=$NFSMAPID_DOMAIN
export TGROUP=$TGROUP
export TGID=$TGID
export TUSER01=$TUSER01
export TUID01=$TUID01
export TUSER02=$TUSER02
export TUID02=$TUID02
export IS_IPV6=$IS_IPV6
export _NFS_STF_DEBUG=$_NFS_STF_DEBUG
export NFSGEN_DEBUG=$NFSGEN_DEBUG
export PATH=$PATH:/opt/SUNWstc-genutils/bin
EOF
RUN_CHECK scp $DIR/srv_setup                   \
    $STF_TMPDIR/srv_env.vars                   \
    $STF_TOOLS/contrib/include/libsmf.shlib    \
    $STF_TOOLS/contrib/include/nfs-smf.kshlib  \
    $STF_SUITE/include/nfs-util.kshlib \
    root@$SERVER:$SRV_TMPDIR || exit $STF_UNINITIATED

# Run server setup script
RUN_CHECK RSH root $SERVER "$SRV_TMPDIR/srv_setup -s" || exit $STF_UNINITIATED


#
# General client2 side setup
#	- creating test user
#	- setting up nfsmapid domain
#

if [[ -n $CLIENT2 && $CLIENT2 != $SERVER && $CLIENT2 != $CLIENT ]]; then
	# Create temp dir on client2
	RUN_CHECK RSH root $CLIENT2 "mkdir -p -m 0777 $SRV_TMPDIR" \
		|| exit $STF_UNINITIATED
	# copy files
	RUN_CHECK scp $DIR/srv_setup                   \
		$STF_TMPDIR/srv_env.vars                   \
		$STF_TOOLS/contrib/include/libsmf.shlib    \
		$STF_TOOLS/contrib/include/nfs-smf.kshlib  \
		$STF_SUITE/include/nfs-util.kshlib \
		root@$CLIENT2:$SRV_TMPDIR || exit $STF_UNINITIATED

	# Run server setup script
	RUN_CHECK RSH root $CLIENT2 "$SRV_TMPDIR/srv_setup -s" \
		|| exit $STF_UNINITIATED
fi

#
# Setup-specific configuration.
#
# We move share and mount operations there for flexibility. However,
# they should use SHRDIR, SHROPT, MNTDIR, and MNTOPT variables.
#

RUN_CHECK ${STF_SUITE}/bin/$SETUP/configure $1 || exit $STF_UNINITIATED

# Check the setup
RUN_CHECK touch $MNTDIR/testfile || exit $STF_UNINITIATED
RUN_CHECK rm $MNTDIR/testfile || exit $STF_UNINITIATED

exit $STF_PASS
