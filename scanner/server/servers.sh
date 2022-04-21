udpPath='/home/student/IPK/scanner/server/udp.py'
ports=(1111 1234 1329 1395 1500 17897 18345 26324 40256 65535)

udpProcesses=()
tcpProcesses=()
# create 5 UDP/TCP servers with python
for port in ${ports[@]}; do
    # UDP
    python3 $udpPath $port &
    udpProcesses+=("$!")
    #TCP
    python3 -m http.server $port &
    tcpProcesses+=("$!")
done

read userInput

allProcesses=( "${udpProcesses[@]}" "${tcpProcesses[@]}" )
for process in ${allProcesses[@]}; do
    kill $process
done
