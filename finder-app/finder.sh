#!/bin/sh

#echo "Call: $0 $@"

if [ $# -lt 2 ]; then
	echo "Usage: finder.sh filesdir searchstr"
	exit 1
fi
FILESDIR=$1
if [ ! -d "$FILESDIR" ]; then 
	echo "First argument is not a directory"
	exit 1
fi

#echo "Contents of $FILESDIR:"
#echo $(ls -1 "$FILESDIR")

SEARCHSTR=$2
X=$(ls -1 "$FILESDIR" | wc -l)
Y=$(grep $SEARCHSTR "$FILESDIR"/* | wc -l)
echo "The number of files are $X and the number of matching lines are $Y"
exit 0
