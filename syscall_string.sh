#!/bin/sh

H=
for d in /usr/include/asm /usr/include/x86_64-linux-gnu/asm
do
	if [ -f $d/unistd_64.h ]
	then
		H=$d/unistd_64.h
		break
	fi
done
if [ X$H = X ]; then
	echo unistd_64.h not found >&2
	exit 1
fi

grep __NR_ $H |
	sed 's/__NR_//' |
	awk 'BEGIN { print "static char *syscall_list[] = {" }
	     { print "[" $3 "] = \"" $2 "\"," }
	     END { print "};" }'

cat <<EOF

const char *
syscall_string(int num)
{
	if (num < 0 || num >= sizeof(syscall_list) / sizeof(syscall_list[0]) ||
			syscall_list[num] == 0)
		return ("unknown");
	return (syscall_list[num]);
}
EOF
