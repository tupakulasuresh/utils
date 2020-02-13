#!/bin/bash

#################################################################################
#author:suresh_babu.tupakula@alcatel-lucent.com
#description : This script can be used to extract a portion of file between 
#              2 matched lines in the file
#################################################################################


# Parsing the command line arguments
outputfile=""
while [ "$#" -gt 0 ]; do
	opt=$1
	case $opt in
	     -s)
		 shift 1
		 str1=$1;;
	     -e)
		 shift 1
		 str2=$1;;
	     -f)
		 shift 1
		 fileName=$1;;
	     -o)
		 shift 1
		 outputfile=$1;;
	     -h|--help)
		 echo "This script can be used to extract info from a file between 2 matched lines"
		 echo "For ex: Extract the info from messages file that got logged during 2 script execution"
		 echo "USAGE: extractLog.sh -f <filename> -s <str1> [-e <str2>] [-o <output filename>] [-h|--help]"
		 echo "-f -> to specify filename"
		 echo "-s -> to specify 1st string to be matched"
		 echo "-e -> to specify 2nd string to be matched. If not specified, will extract till the last line of the specified file"
		 echo "-o -> to specify output file in which the extract to be placed. Defaults to $outputfile"
		 echo "-h|--help -> to get help about this script"
		 exit 0;;
	     *)
   	         echo "INVALID SWITCH $opt"
	         echo "VALID are -s -e -f -h"
	         exit 0;;
	esac
        shift 1
done

# validating the log file existence
if [ -z "$fileName" ]; then
    echo "specify the input file name"
    exit 0
elif [ ! -f "$fileName" ]; then
    echo "File $fileName doesn't exists"
    exit 0
fi

script_start_pattern="MASTER: BEGIN ::TestDB::TestCase::.*"
script_end_pattern="MASTER: END ::TestDB::TestCase::.*"

# check if the 1st match string is specified
# also verify if it is present in the log file
if [ -z "$str1" ]; then
    echo "specify the 1st string to be matched"
    exit 0
else 
    stLine=`grep -n "${script_start_pattern}${str1}" $fileName | cut -d : -f1 | head -1` 
    if [ -z "$stLine" ]; then
         echo "No match found for string \"${script_start_pattern}${str1}\" in $fileName"
	 exit 0
    fi
fi

if [ -z ${outputfile} ]; then
    outputfile="${str1}.txt"
fi

# check if the 2nd match string is specified
# if not specified, take the immediate script that is launched after 1st match
# if specified, check its present in the log file
# if both above conditions fail, dump from 1st match till the last line
if [ -z "$str2" ]; then
    # echo "Not specified the end test case. Considering immediate next script"
    # str2=`sed -n "/$str1/,/$script_end_pattern/p" $fileName | grep -o -m2 "$script_end_pattern.*" | awk '{print $(NF-1)}' | sed '1d'`
    # echo "Next script is \"$str2\""
	str2="${script_end_pattern}${str1}"
else
    str2="${script_start_pattern}${str2}"
fi

if [  -z "$str2" ]; then
    echo "Not able to extract the immediate next script name. Will take data till last line"
else 
    endLine=`grep -n "${str2}" $fileName | cut -d : -f1 | head -1` 
    if [ -z "$endLine" ]; then
         echo "No match found for string \"$str2\" in $fileName. "
    else
      endLine=$((endLine - 1))
    fi
fi

if [ -z "$endLine" ]; then
    echo "Extracting info till the last line of $fileName file"
    endLine=`wc -l $fileName | cut -d " " -f1`
fi

# Take the last match in the file
stLine=`echo $stLine |awk -F " " '{print $NF}'`
endLine=`echo $endLine |awk -F " " '{print $NF}'`
extractedLines=`echo "$endLine - $stLine + 1" | bc`

echo "Dumping $extractedLines lines of info (between line#$stLine and line#$endLine) from $fileName at $outputfile"

sed -n $stLine,"$endLine"p $fileName > $outputfile 
