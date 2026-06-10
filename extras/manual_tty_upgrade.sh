#!/bin/bash

WAIT=5

echo "Go to the UNIX shell that needs upgrade"

while [ $WAIT -gt 0 ]
do
echo Seconds left: "$WAIT"
sleep 1
WAIT=`expr $WAIT - 1`
done

ROWS=`tput lines`
COLUMNS=`tput cols`

xdotool type $'python3 -c "import pty; pty.spawn(\'/bin/bash\')" || python -c "import pty; pty.spawn(\'/bin/bash\')"'
xdotool key Return
xdotool type 'export TERM=xterm-256color'
xdotool key Return
xdotool type 'export SHELL=/bin/bash'
xdotool key Return
xdotool key ctrl+z
xdotool type 'stty raw -echo;fg'
xdotool key Return
xdotool type "stty rows $ROWS columns $COLUMNS"
xdotool key Return
xdotool type reset
xdotool key Return

