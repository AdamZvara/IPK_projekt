udpPath='udp.py'
ports=(1234 8034 16790 35075 65535)

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
