#!/bin/bash

#############################################################################################
#author:suresh_babu.tupakula@alcatel-lucent.com
#description : script to remove unwanted (control characters) from the script execution logs
#############################################################################################

# usage function
function USAGE ()
{
     echo -e "\nUSAGE: $0 <filename>"
     exit 0
}

# validating section
if [ $# -eq 0 -o $# -gt 1 ]; then 
     USAGE
elif [ ! -f $1 ]; then
     echo "\"$1\" : No such file"
     USAGE
fi

# pattern to remove colors from the script log
sed -i 's/\|\|\[..m\|\[0m\|\[@\|\(\(\[\(.\|\\\).\);..m\)\|\(\].\)\|\(_.*\(\\\|\]0;~\)\)\|\[K//g' $1
