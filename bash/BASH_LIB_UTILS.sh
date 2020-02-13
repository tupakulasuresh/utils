t1=$(date +%s)
__TIME_STAMP__=1

function boxify()
{
    size=$(echo $1 | wc -c)
    if [ -z $2 ]; then
        width=1
    else
        width=$2
    fi
    size=$((size+width))
    line=$(printf "%${size}s" | tr ' ' '-')
    space=$(printf "%${width}s")
    #line=$(seq  -s"-" 0 ${size} | sed -e 's/[0-9]//g')
    #space=$(seq  -s" " 0 ${width} | sed -e 's/[0-9]//g')
    echo $line
    echo "${space}$1"
    echo $line
}


function get_ip_addr()
{

    echo $(nslookup $1 | grep -1 Name | grep Address | cut -d ":" -f 2)
}

function getip()
{
    echo $(get_ip_addr $1)
}

function toTitle()
{
    echo $1 | sed -e 's/[a-z]*/\u&/'
}

function get_node_info()
{
    i=1
    while [ $i -le 10 ]; do 
        node=${testbed}-${1}${i}
        ip=$(get_ip_addr $node)
        if [ -z ${ip} ]; then
            break
        fi
        if [ $(echo $1 | grep -c "leaf\|spine") -gt 0 ]; then
            NODE_IP_LIST="${NODE_IP_LIST} ${ip}"
        elif [ $(echo $1 | grep -c "n3k") -gt 0 ]; then
            N3K_IP_LIST="${N3K_IP_LIST} ${ip}"
        else
            APIC_IP_LIST="${APIC_IP_LIST} ${ip}"
        fi
        i=$((i+1))
    done
}

function execute_via_ssh()
{
    ip=$1
    shift 1
    cmd="$*"

    if [ $(echo $N3K_IP_LIST | grep -c $ip) -gt 0 ]; then 
        passwd=$N3K_PASSWD
    else
        passwd=$REMOTE_PASSWD
    fi
    timeout -s 9 60 \
    sshpass -p "${passwd}" ssh -q -n \
            -o "StrictHostKeyChecking=no" \
            -o "UserKnownHostsFile=/dev/null" \
            ${REMOTE_USER}@$ip \
            "$cmd"
}

function cleanup_nodes()
{

    method=$1

    for node_type in APIC LEAF/SPINE; do
        if [ $node_type == "APIC" ]; then
            IP_LIST=${APIC_IP_LIST}
            if [ $method == "clean" ]; then
                cmd_list="acidiag touch clean ; sleep 1 ; sync"
            else 
                cmd_list="acidiag reboot"
            fi
        else
            IP_LIST=${NODE_IP_LIST}
            if [ $method == "clean" ]; then
                cmd_list="setup-clean-config.sh"
            else 
                cmd_list="reload"
            fi
        fi
        #cmd_list="show version"
             
        echo "Cleaning $node_type ..."
        for ip in ${IP_LIST}; do
            echo "  Node $ip ..."
            execute_via_ssh $ip "$cmd_list" &
        done
    done
    echo "Waiting for task to complete ..."
    wait
}

function waitfor()
{
    count=$1
    while true; do
        tput el1
        echo -ne "\rWaiting for ${1}s .... [Remaining time: ${count}s]"
        count=$((count - 1))
        if [ $count -lt 0 ]; then
            break
        fi
        sleep 1
    done
    echo ""
}


function monitor_nodes()
{
    IP_LIST="${APIC_IP_LIST} ${NODE_IP_LIST} ${N3K_IP_LIST}"
    for ip in ${IP_LIST}; do
        echo -n " Monitoring $ip ... "
        i=1
        while [ $i -le 600 ]; do 
            if [ $(ping -nq -c 1  ${ip} | grep -c "1 received") -eq 0 ]; then
                sleep 2
                i=$((i+1))
            else
                echo "[UP]"
                i=0
                break
            fi
        done 
        if [ $i -gt 0 ]; then
            echo "[Down]"
        fi
    done
}

function update_nodes()
{

    testbed="ifav69"

    if [ $# -gt 0 ]; then 
        if [ $(echo $1 | grep -c "^[0-9]\+$") -ge 1 ]; then
            testbed="ifav${1}"
        else
            testbed=$1
        fi
    fi

    boxify "Testbed is $testbed" 

    NODE_IP_LIST=""
    APIC_IP_LIST=""
    N3K_IP_LIST=""
    REMOTE_USER="admin"
    REMOTE_PASSWD="ins3965!"
    N3K_PASSWD="Insieme123"


    get_node_info "leaf"
    get_node_info "spine"
    get_node_info "apic"
    #get_node_info "ifc"
    get_node_info "n3k-"
}

function is_mac()
{

    if [ $(uname -s) == 'Darwin' ]; then
        echo true
    else
        echo false
    fi 

}

function get_work_dir()
{
    if [ $(is_mac) == 'true' ]; then
        if [ x${1} == "xremote" ]; then 
            echo /home/$(whoami)
        else
            echo /Users/$(whoami)
        fi
    else
        if [ x${1} == "xremote" ]; then 
            echo /Users/$(whoami)
        else
            echo /home/$(whoami)
        fi
    fi
}

function get_home_dir()
{
    if [ $(is_mac) == 'true' ]; then
        if [ x${1} == "xremote" ]; then 
            echo /home/$(whoami)
        else
            echo /Users/$(whoami)
        fi
    else
        if [ x${1} == "xremote" ]; then 
            echo /Users/$(whoami)
        else
            echo /home/$(whoami)
        fi
    fi
}

function get_remote_node()
{
    if [ $(is_mac) == 'true' ]; then
        echo $MY_VM
    else
        echo $MY_MAC
    fi
}



function reboot_nodes()
{
    cleanup_nodes "clean"
    cleanup_nodes "reboot"
}

function log_msg()
{
    options=""
    # retrieve all options before message
    while [ $# -gt 1 ]; do
        options="$options $1"
        shift 1
    done
    msg=$1

    if [ ${__TIME_STAMP__} == 0 ]; then 
        echo $msg
        __TIME_STAMP__=1
    else
        echo $options "[$(date "+%d-%b-%y %T")] $msg"
        if [ $(echo "\\$options" | grep -c -- "-n") -gt 0 ]; then
            __TIME_STAMP__=0
        fi
    fi 
}

function time_taken()
{
    if [ $# -eq 0 ]; then
        initial_time=$t1
    else
        intial_time=$1
    fi
    echo "[Time Taken : $(echo "$(date +%s) - $initial_time" | bc)s]"

}
