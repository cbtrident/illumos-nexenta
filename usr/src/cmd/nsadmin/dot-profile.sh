#
# Want XPG6 commands. See standards(5).
# Use less(1) as the default pager for the man(1) command.
#
export PATH=/usr/xpg6/bin:/usr/xpg4/bin:/usr/bin:/usr/sbin:/sbin
export PAGER="/usr/bin/less -ins"

# Uncommenting PATH below will place /usr/gnu/bin at front,
# adds /usr/sbin and /sbin to the end.
#
# export PATH=/usr/gnu/bin:/usr/bin:/usr/sbin:/sbin
#
# Define default prompt to <username>@<hostname>:<path><"($|#) ">
# and print '#' for user "root" and '$' for normal users.
#
# override default prompt for bash
# case "$0" in
# -bash)
#	export PS1="\u@\h:\w\\$ "
# esac
