#!/bin/sh
# DO NOT REMOVE THIS LINE OR THE NEXT! \
exec tclsh "$0" "$@"

# loading expect package
if {[catch { package require Expect } err]} {
     puts "ERROR: This tool requires Expect package on this machine"
     puts "ERROR: $err"
     return -1
}

#############################################################################################
#description : script to login to a specific testbed and get details like wait time in que, time taken for execution etc
#############################################################################################

proc execute_command {testbed cmd {expTimeOut 100}} {
     set sess_id [connect_to_dut $testbed]
     exp_internal 0

     set timeout $expTimeOut
     set return_result ""

     set prompt "#|\\$|>"

     if {[regexp "^tail -f" $cmd]} { set prompt "__UNKNOWN__" }

     send -i $sess_id "$cmd\n"
     expect {
          -i $sess_id -re $prompt        { }
          -i $sess_id -re "assword"      { send -i $sess_id $::PASSWORD\r ; exp_continue }
          -i $sess_id full_buffer { if {![regexp "^tail -f" $cmd]} { append return_result $expect_out(buffer) } ; exp_continue }
          -i $sess_id timeout {
               puts "STATUS   : FAIL"
               puts "REASON   : Expect session timedout during copying"
               exit 1
          }
     }
     if {[regexp "^tail -f" $cmd]} { return "" }

     if {[info exists expect_out(buffer)]} { append return_result $expect_out(buffer) }
     return [string trim [join [lrange [split $return_result "\n\r"] 1 end-1] "\n"]]
}

proc connect_to_dut {testbed} {
     global ARR_USER_SESSION
     if {![info exists ARR_USER_SESSION($testbed)]} {
          set tb_ip $testbed
          log_user 0
          set ret_val 0
          spawn telnet $tb_ip
          expect {
               -re "\n(L|l)ogin:" { send "$::USERNAME\r" ; exp_continue }
               -re "word:"        { send "$::PASSWORD\r" ; exp_continue }
               -re "#|\\$|>"      { }
               timeout            {
                    puts "ERROR: cannot access $testbed ... aborting"
                    exit 1
               }
          }
          set ARR_USER_SESSION($testbed) $spawn_id
     }

     return $ARR_USER_SESSION($testbed)
}

proc USAGE {} {
     puts "[info script] \[-t|--testbed <testbed_name>\] \[--(no-)retry\] \[--date <date in mm/dd/yyyy format>\] \[--time <time in H:M:S format>\] \[--file <source file>\] \[--dest_file <to rename the copied file>\] \[--user <user_name>\]"
     puts ""
     puts "testbed     : name of the testbed which needs to be accesed ... ex : ipsec1, mvhwipsec1. default is owner's linux controller"
     puts "\[no\]retry   : to retry or not accesing this log file. helpful when log file is not yet created"
     puts "date        : from date.  default is today's date"
     puts "time        : time"
     puts "file        : source file name (default is test_console.txt"
     puts "dest_file   : how the source file to be stored locally"
     puts "user        : owner of the regression job"
     puts ""
     exit 0
}

proc main {} {

     if {[regexp -- "-h|--help" $::argv]} { USAGE }

     set ::USERNAME "root"
     set ::PASSWORD "tigris"

     set testbed    [eval exec whoami]
     set date       [clock format [clock seconds] -format "%x"]
     set time       ""
     set file_name  "test_console.txt"
     set user       "Suresh_Babu.Tupakula"
     set debug      "false"
     set retry      "true"
     set interval   "5"

     for {set i 0} {$i < $::argc} {incr i} {
          switch -regexp -- [lindex $::argv $i] {
               "^(--debug)$"           { set debug true }
               "^(--retry)$"           { set retry true }
               "^(--noretry)$"         { set retry false }
               "^(-t|--testbed)$"      { incr i ; set testbed [lindex $::argv $i] }
               "^(--date)$"            { incr i ; set date [lindex $::argv $i] }
               "^(--time)$"            { incr i ; set time [lindex $::argv $i] }
               "^(--file)$"            { incr i ; set file_name [lindex $::argv $i] }
               "^(--user)$"            { incr i ; set user [lindex $::argv $i] }
               "^(--interval)$"        { incr i ; set interval [lindex $::argv $i] }
               default                 { puts "[lindex $::argv $i] : not a supported option\n\n" ; USAGE }
          }
     }

     # validating data
     foreach var "date time" format "x T" {
          if {[set $var] == ""} { continue }
          if {[catch {
                    set $var [clock scan [set $var]]
                    set $var [clock format [set $var] -format %$format]
               } err]} {
               puts "$var is not a valid date format. Got [set $var]"
               USAGE
          }
     }

     if {[regexp "^ipsec" $testbed]} { set testbed "mvhw$testbed" } elseif {[regexp "^\\d+$" $testbed]} { set testbed "mvhwipsec$testbed" }

     foreach {day mon year}  [clock format [clock scan $date] -format "%b_%d Month_%m %Y"] {break}

     set path "/$testbed/results/$year/$mon/"
     if {$time != "" && $user != ""} { append path ${time}.${user} }

     execute_command $testbed "stty columns 1000"

     set cmd "find $path -name \"test_console*.txt\" -mmin -1"
     # use bash shell and to handle lengthy commands sending to expect
     while {1} {
          set fileName [execute_command $testbed $cmd]
          if {$fileName == ""} {
               if {$retry} {
                    puts "NOTICE : Log file is not yet avialable. Will check after ${interval}s"
                    sleep $interval
                    continue
               } else {
                    puts "NOTICE: Not found test_console.txt that is being updated now on $testbed. Check your inputs or retry after some time"
                    return 1
               }
          } else {
               break
          }
     }

     log_user 1
     set cmd "tail -f $fileName"
     set result [execute_command $testbed $cmd "-1"]

     return
}

return [main]
