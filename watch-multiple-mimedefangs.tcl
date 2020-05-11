#!/bin/sh
# -*-Mode: TCL;-*-
#
# Copyright (C) 2007 Roaring Penguin Software Inc.  This file may be
# distributed under the terms of the GNU General Public License, Version 2,
# or (at your option) any later version.

# Next line restarts using wish \
exec wish "$0" -- "$@" ; clear; echo "*****"; echo "Cannot find 'wish' -- you need Tcl/Tk installed to run this program"; exit 1

# Main update interval (ms)
set MainUpdateInterval 1500

# Busy worker update interval (ms)
set BusyWorkerUpdateInterval 3000

# Trace command - pid is appended
set TraceCommand "strace -s 100 -t -p"

# Command to run SSH
set SSHCommand "ssh"

# Command to run md-mx-ctrl
set MD_MX_CTRL "md-mx-ctrl -i"

# Archive readings?
set DoArchive 0

# Have we done a redraw since the last update?
# Start out set to yes to kick things off!
set DoneARedrawSinceLastUpdate 1

# Use new-style "rawload1" command?
set NewStyle 0
set NewStyleShowScans 0
set NewStyleShowRelayoks 0
set NewStyleShowSenderoks 0
set NewStyleShowRecipoks 0

# Time scale for graph y-axes (seconds)
set NewStyleTimeInterval 1

set MachinesAwaitingReply {}

if {[info exists env(MD_MX_CTRL)]} {
    set x $env(MD_MX_CTRL)
    if {"$x" != ""} {
	set MD_MX_CTRL $x
    }
}

proc strip_zeros { num } {
    return [regsub {\.0+$} $num ""]
}

# Don't edit anything below here!
set Machines {}
set ctr 0
set after_token {}
proc find_machine { mach } {
    global Machines
    set index 0
    foreach m $Machines {
	if {"[lindex $m 0]" == "$mach"} {
	    return $index
	}
	incr index
    }
    return -1
}

proc add_machine { mach } {
    if {[find_machine $mach] >= 0} {
	return
    }

    global Machines
    if {[catch {
	set fp [open_connection $mach]
	lappend Machines [list $mach $fp]
    } err]} {
	puts stderr $err
    }
}

proc host_plus_user { mach } {
    if { [string match "*@*" $mach] } {
	return $mach
    }
    return "root@$mach"
}

proc del_machine { mach } {
    global Machines
    global Data
    set mnew {}
    set index 0
    set did_something 0
    foreach m $Machines {
	if { "[lindex $m 0]" == "$mach"} {
	    catch {
		close [lindex $m 1]
	    }
	    catch { unset Data($mach,busy) }
	    catch { unset Data($mach,time) }
	    catch { unset Data($mach,persec) }
	    catch { unset Data($mach,busy_snap) }
	    catch { unset Data($mach,persec_snap) }
	    catch { unset Data($mach,time_snap) }
	    catch { unset Data($mach,qsize) }
	    catch { unset Data($mach,busyworkerwin) }
	    catch { unset Data($mach,busyworkerafter) }
	    catch { unset Data($mach,error) }
	    set did_something 1
	    continue
	}
	lappend mnew $m
    }
    set Machines $mnew
    if {$did_something} {
	reconfigure
    }
}

proc open_connection { mach } {
    global SSHCommand
    global MD_MX_CTRL
    set hmach [host_plus_user $mach]
    set fp [open "| $SSHCommand $hmach $MD_MX_CTRL" "r+"]
    fconfigure $fp -blocking 0
    #fconfigure $fp -translation binary
    fileevent $fp readable [list connection_readable $mach $fp]
    return $fp
}

proc connection_readable { mach fp } {
    global DoArchive
    global MachinesAwaitingReply
    global after_token

    # Delete from MachinesAwaitingReply
    set index [lsearch -exact $MachinesAwaitingReply $mach]
    if {$index >= 0} {
	set MachinesAwaitingReply [lreplace $MachinesAwaitingReply $index $index]
    }
    gets $fp line

    if {"$line" == ""} {
	if {[eof $fp]} {
	    catch { close $fp }
	    del_machine $mach
	}
    } else {
	set index [find_machine $mach]
	if {$index >= 0} {
	    if {[catch { update_machine $line $index $mach } err]} {
		mach_set_status_error $mach $index $err
	    }

	    if {$DoArchive} {
		if {[catch { log_stats $mach $line } err]} {
		    puts stderr $err
		}
	    }
	}
    }

    # If all machines have replied, redraw
    if {[llength $MachinesAwaitingReply] == 0} {
	if {"$after_token" != ""} {
	    after cancel $after_token
	    set after_token {}
	}
	redraw
    }
}

proc log_stats { mach line } {
    set dir "~/.watch-multiple-mimedefangs/$mach"
    if {![file isdirectory $dir]} {
	file mkdir $dir
    }
    set fp [open "$dir/data" "a"]
    puts $fp "[clock seconds] $line"
    close $fp
}

proc get_machine_windows { } {
    set kids [winfo children .top]
    set result {}
    set hi 0
    foreach k $kids {
	if {[regexp {^\.top\.name([0-9]+)$} $k dummy index]} {
	    if {$index > $hi} {
		set hi $index
	    }
	}
    }
    foreach k $kids {
	if {[regexp {^\.top\.[^0-9]+([0-9]+)$} $k dummy index]} {
	    if {$index <= $hi} {
		lappend result $k
	    }
	}
    }
    return $result
}

proc mach_set_status_error { mach index err } {
    global Data
    set Data($mach,error) 1
    .top.name$index configure -foreground red
    .top.c$index itemconfigure statusText -text $err
    .top.c$index delete withtag data1
    .top.c$index delete withtag data2
    .top.c$index delete withtag data3
}

proc mach_set_status_normal { mach index status } {
    global Data
    set Data($mach,error) 0
    .top.name$index configure -foreground black
    .top.c$index itemconfigure statusText -text $status
}

proc mach_populate_data { mach index line } {
    global Data
    global NewStyle

    if {$NewStyle} {
	mach_populate_data_new_style $mach $index $line
	return
    }

    foreach { msg0 msg1 msg5 msg10 busy0 busy1 busy5 busy10 ms0 ms1 ms5 ms10 a0 a1 a5 a10 r0 r1 r5 r10 busy idle stopped killed msgs activations qsize qnum uptime} $line { break }
    set total_workers [expr $busy + $idle + $stopped + $killed]
    set ms0 [format "%.0f" $ms0]
    set msg0 [format "%.2f" [expr $msg0 / 10.0]]

    lappend Data($mach,busy) $busy0
    lappend Data($mach,time) $ms0
    lappend Data($mach,persec) $msg0
    set Data($mach,total_workers) $total_workers
    set Data($mach,busy_snap) $busy
    set Data($mach,persec_snap) $msg0
    set Data($mach,time_snap) $ms0
    set Data($mach,qsize) $qsize
    schedule_redraw
}

proc mach_populate_data_new_style { mach index line } {
    global Data
    foreach { scans avgbusyscans scantime relayoks avgbusyrelayoks relayoktime senderoks avgbusysenderoks senderoktime recipoks avgbusyrecipoks recipoktime busyworkers idleworkers stoppedworkers killedworkers msgs activations qsize numqueued uptime back } $line { break }

    set scantime [format "%.0f" $scantime]
    set relayoktime [format "%.0f" $relayoktime]
    set senderoktime [format "%.0f" $senderoktime]
    set recipoktime [format "%.0f" $recipoktime]

    set total_workers [expr $busyworkers + $idleworkers + $stoppedworkers + $killedworkers]

    set back [expr 1.0 * $back]
    set scanspersec [expr (1.0 * $scans) / $back ]
    set relayokspersec [expr (1.0 * $relayoks) / $back ]
    set senderokspersec [expr (1.0 * $senderoks) / $back ]
    set recipokspersec [expr (1.0 * $recipoks) / $back ]

    set scanspersec [format "%.2f" $scanspersec]
    set relayokspersec [format "%.2f" $relayokspersec]
    set senderokspersec [format "%.2f" $senderokspersec]
    set recipokspersec [format "%.2f" $recipokspersec]

    lappend Data($mach,busy) $busyworkers
    lappend Data($mach,scantime) $scantime
    lappend Data($mach,scanspersec) $scanspersec
    lappend Data($mach,relayoktime) $relayoktime
    lappend Data($mach,relayokspersec) $relayokspersec
    lappend Data($mach,senderoktime) $senderoktime
    lappend Data($mach,senderokspersec) $senderokspersec
    lappend Data($mach,recipoktime) $recipoktime
    lappend Data($mach,recipokspersec) $recipokspersec

    set Data($mach,total_workers) $total_workers
    set Data($mach,busy_snap) $busyworkers
    set Data($mach,scanspersec_snap) $scanspersec
    set Data($mach,relayokspersec_snap) $relayokspersec
    set Data($mach,senderokspersec_snap) $senderokspersec
    set Data($mach,recipokspersec_snap) $recipokspersec
    set Data($mach,scantime_snap) $scantime
    set Data($mach,relayoktime_snap) $relayoktime
    set Data($mach,senderoktime_snap) $senderoktime
    set Data($mach,recipoktime_snap) $recipoktime
    set Data($mach,qsize) $qsize
    set Data($mach,numqueued) $numqueued

    schedule_redraw
}

proc schedule_redraw {} {
    global MainUpdateInterval
    global after_token
    if {"$after_token" == ""} {
	set after_token [after $MainUpdateInterval redraw]
    }
}

proc redraw_new_style {} {
    global Machines
    global after_token
    global Data
    global TotalData
    global NewStyleShowScans NewStyleShowRelayoks NewStyleShowSenderoks NewStyleShowRecipoks

    set after_token ""
    set index 0

    set scanspersec_total 0
    set relayokspersec_total 0
    set senderokspersec_total 0
    set recipokspersec_total 0
    set scantime_total 0
    set relayoktime_total 0
    set senderoktime_total 0
    set recipoktime_total 0
    set busyworkers_total 0
    set totalworkers_total 0
    set busyworkers_active 0
    set totalworkers_active 0
    set num_machines 0

    set num_graphs 1
    if {$NewStyleShowScans} {
	incr num_graphs 2
    }
    if {$NewStyleShowRelayoks} {
	incr num_graphs 2
    }
    if {$NewStyleShowSenderoks} {
	incr num_graphs 2
    }
    if {$NewStyleShowRecipoks} {
	incr num_graphs 2
    }

    set wid [winfo width .top.clabels]
    .top.clabels delete all
    set spacing [expr $wid / (1.0 * $num_graphs)]
    set x [expr $spacing / 2.0]
    .top.clabels create text $x 2 -anchor n -fill "#A00000" -text "Busy Workers"
    if {$NewStyleShowScans} {
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#00A000" -text "Scans/d"
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#0000A0" -text "ms/scan"
    }
    if {$NewStyleShowRelayoks} {
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#808000" -text "Relays/d"
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#008080" -text "ms/relay"
    }
    if {$NewStyleShowSenderoks} {
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#808080" -text "Senders/d"
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#800080" -text "ms/sender"
    }
    if {$NewStyleShowRecipoks} {
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#008000" -text "Recips/d"
	set x [expr $x + $spacing]
	.top.clabels create text $x 2 -anchor n -fill "#000000" -text "ms/recip"
    }

    foreach m $Machines {
	set mach [lindex $m 0]
	if {![info exists Data($mach,busy)]} {
	    incr index
	    continue
	}
	if {$Data($mach,error)} {
	    incr index
	    continue
	}

	# Update totals
	set busy $Data($mach,busy_snap)
	set totalworkers $Data($mach,total_workers)

	# Only update worker counts for machines that are actually doing something
	if {$Data($mach,scanspersec_snap) > 0 || $Data($mach,relayokspersec_snap) > 0 || $Data($mach,senderokspersec_snap) > 0 || $Data($mach,recipokspersec_snap) > 0} {
	    set totalworkers_active [expr $totalworkers_active + $totalworkers]
	    set busyworkers_active [expr $busyworkers_active + 1.0*$busy]
	}

	set totalworkers_total [expr $totalworkers_total + $totalworkers]
	set busyworkers_total [expr $busyworkers_total + 1.0*$busy]

	set scanspersec_total [expr $scanspersec_total + 1.0*$Data($mach,scanspersec_snap)]
	set scantime_total [expr $scantime_total + (1.0*$Data($mach,scanspersec_snap) * $Data($mach,scantime_snap))]
	set relayokspersec_total [expr $relayokspersec_total + 1.0*$Data($mach,relayokspersec_snap)]
	set relayoktime_total [expr $relayoktime_total + (1.0*$Data($mach,relayokspersec_snap) * $Data($mach,relayoktime_snap))]
	set senderokspersec_total [expr $senderokspersec_total + 1.0*$Data($mach,senderokspersec_snap)]
	set senderoktime_total [expr $senderoktime_total + (1.0*$Data($mach,senderokspersec_snap) * $Data($mach,senderoktime_snap))]
	set recipokspersec_total [expr $recipokspersec_total + 1.0*$Data($mach,recipokspersec_snap)]
	set recipoktime_total [expr $recipoktime_total + (1.0*$Data($mach,recipokspersec_snap) * $Data($mach,recipoktime_snap))]

	set graph 0
	set Data($mach,busy) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 $Data($mach,total_workers) $Data($mach,busy) $index "Busy" $graph "#A00000" 1]
	if {$totalworkers > 0} {
	    set pctbusy [expr int((1.0*$busy) / (1.0*$totalworkers) * 100)]
	} else {
	    set pctbusy 100
	}
	if {$pctbusy < 80} {
	    .top.busy$index configure -background #D9D9D9 -foreground "#A00000"
	} elseif {$pctbusy < 90} {
	    .top.busy$index configure -background #C0C000 -foreground "#A00000"
	} else {
	    .top.busy$index configure -background #C00000 -foreground "#000000"
	}

	.top.busy$index configure -text "$busy/$totalworkers\n$pctbusy%"

	incr graph

	if {$NewStyleShowScans} {
	    set Data($mach,scanspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,scanspersec) $index "Scans/s" $graph "#00A000" 1]
	    incr graph
	    set Data($mach,scantime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,scantime) $index "ms/scan" $graph "#0000A0" 1]
	    incr graph
	    set s $Data($mach,scanspersec_snap)
	    set h [human_number [expr $s * 3600]]
	    set d [human_number [expr $s * 86400]]
	    if {$s == 0} {
		.top.scanspersec$index configure -text "-"
		.top.scantime$index configure -text "-"
	    } else {
		.top.scanspersec$index configure -text [format "%.2f\n%s/h\n%s/d" $s $h $d]
		.top.scantime$index configure -text $Data($mach,scantime_snap)
	    }
	} else {
	    set Data($mach,scanspersec) {}
	    set Data($mach,scantime) {}
	}

	if {$NewStyleShowRelayoks} {
	    set Data($mach,relayokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,relayokspersec) $index "Relayoks/s" $graph "#808000" 1]
	    incr graph
	    set Data($mach,relayoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,relayoktime) $index "ms/relayok" $graph "#008080" 1]
	    incr graph
	    set s $Data($mach,relayokspersec_snap)
	    set h [human_number [expr $s * 3600]]
	    set d [human_number [expr $s * 86400]]
	    if {$s == 0} {
		.top.relayspersec$index configure -text "-"
		.top.relaytime$index configure -text "-"
	    } else {
		.top.relayspersec$index configure -text [format "%.2f\n%s/h\n%s/d" $s $h $d]
		.top.relaytime$index configure -text $Data($mach,relayoktime_snap)
	    }
	} else {
	    set Data($mach,relayokspersec) {}
	    set Data($mach,relayoktime) {}
	}
	if {$NewStyleShowSenderoks} {
	    set Data($mach,senderokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,senderokspersec) $index "Senderoks/s" $graph "#808080" 1]
	    incr graph
	    set Data($mach,senderoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,senderoktime) $index "ms/senderok" $graph "#800080" 1]
	    incr graph
	    set s $Data($mach,senderokspersec_snap)
	    set h [human_number [expr $s * 3600]]
	    set d [human_number [expr $s * 86400]]
	    if {$s == 0} {
		.top.senderspersec$index configure -text "-"
		.top.sendertime$index configure -text "-"
	    } else {
		.top.senderspersec$index configure -text [format "%.2f\n%s/h\n%s/d" $s $h $d]
		.top.sendertime$index configure -text $Data($mach,senderoktime_snap)
	    }
	} else {
	    set Data($mach,senderokspersec) {}
	    set Data($mach,senderoktime) {}
	}
	if {$NewStyleShowRecipoks} {
	    set Data($mach,recipokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,recipokspersec) $index "Recipoks/s" $graph "#008000" 1]
	    incr graph
	    set Data($mach,recipoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $Data($mach,recipoktime) $index "ms/recipok" $graph "#000000" 1]
	    incr graph
	    set s $Data($mach,recipokspersec_snap)
	    set h [human_number [expr $s * 3600]]
	    set d [human_number [expr $s * 86400]]
	    if {$s == 0} {
		.top.recipspersec$index configure -text "-"
		.top.reciptime$index configure -text "-"
	    } else {
		.top.recipspersec$index configure -text [format "%.2f\n%s/h\n%s/d" $s $h $d]
		.top.reciptime$index configure -text $Data($mach,recipoktime_snap)
	    }
	} else {
	    set Data($mach,recipokspersec) {}
	    set Data($mach,recipoktime) {}
	}
	incr index
    }
    lappend TotalData(busy) $busyworkers_total
    lappend TotalData(total) $totalworkers_total
    lappend TotalData(scanspersec) $scanspersec_total
    set scantime_avg [expr $scantime_total / ($scanspersec_total + 0.000000001)]
    set relayoktime_avg [expr $relayoktime_total / ($relayokspersec_total + 0.000000001)]
    set senderoktime_avg [expr $senderoktime_total / ($senderokspersec_total + 0.000000001)]
    set recipoktime_avg [expr $recipoktime_total / ($recipokspersec_total + 0.000000001)]
    lappend TotalData(scantime) $scantime_avg
    lappend TotalData(relayokspersec) $relayokspersec_total
    lappend TotalData(relayoktime) $relayoktime_avg
    lappend TotalData(senderokspersec) $senderokspersec_total
    lappend TotalData(senderoktime) $senderoktime_avg
    lappend TotalData(recipokspersec) $recipokspersec_total
    lappend TotalData(recipoktime) $recipoktime_avg

    set graph 0
    set TotalData(busy) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 $totalworkers_total $TotalData(busy) $index "Busy" $graph "#A00000" 1]
    if {$totalworkers_total > 0} {
	set busyworkers_total [expr int($busyworkers_total)]
	set pctbusy [expr int((1.0 * $busyworkers_total) / (1.0 * $totalworkers_total) * 100)]
    } else {
	set pctbusy 100
    }

    if {$totalworkers_active > 0} {
	set busyworkers_active [expr int($busyworkers_active)]
	set apct [expr int((1.0 * $busyworkers_active) / (1.0 * $totalworkers_active) * 100)]
    } else {
	set apct 100
    }
    .top.busytotal configure -text "$busyworkers_total/$totalworkers_total\n$pctbusy%\n$busyworkers_active/$totalworkers_active\n$apct%"
    incr graph

    if {$NewStyleShowScans} {
	set TotalData(scanspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(scanspersec) $index "Scans/s" $graph "#00A000" 1]
	incr graph
	set TotalData(scantime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(scantime) $index "ms/scan" $graph "#0000A0" 1]
	incr graph
	set h [human_number [expr $scanspersec_total * 3600]]
	set d [human_number [expr $scanspersec_total * 86400]]
	.top.scanspersectotal configure -text [format "%.2f\n%s/h\n%s/d" $scanspersec_total $h $d]
	.top.avgscantime configure -text [format "%.0f" $scantime_avg]
    } else {
	set TotalData(scanspersec) {}
	set TotalData(scantime) {}
    }

    if {$NewStyleShowRelayoks} {
	set TotalData(relayokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(relayokspersec) $index "Relayoks/s" $graph "#808000" 1]
	incr graph
	set TotalData(relayoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(relayoktime) $index "ms/relayok" $graph "#008080" 1]
	incr graph
	set h [human_number [expr $relayokspersec_total * 3600]]
	set d [human_number [expr $relayokspersec_total * 86400]]
	.top.relayspersectotal configure -text [format "%.2f\n%s/h\n%s/d" $relayokspersec_total $h $d]
	.top.avgrelaytime configure -text [format "%.0f" $relayoktime_avg]
    } else {
	set TotalData(relayokspersec) {}
	set TotalData(relayoktime) {}
    }
    if {$NewStyleShowSenderoks} {
	set TotalData(senderokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(senderokspersec) $index "Senderoks/s" $graph "#808080" 1]
	incr graph
	set TotalData(senderoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(senderoktime) $index "ms/senderok" $graph "#800080" 1]
	incr graph
	set h [human_number [expr $senderokspersec_total * 3600]]
	set d [human_number [expr $senderokspersec_total * 86400]]
	.top.senderspersectotal configure -text [format "%.2f\n%s/h\n%s/d" $senderokspersec_total $h $d]
	.top.avgsendertime configure -text [format "%.0f" $senderoktime_avg]
	set s [human_number $senderokspersec_total]
    } else {
	set TotalData(senderokspersec) {}
	set TotalData(senderoktime) {}
    }
    if {$NewStyleShowRecipoks} {
	set TotalData(recipokspersec) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(recipokspersec) $index "Recipoks/s" $graph "#008000" 1]
	incr graph
	set TotalData(recipoktime) [graph [expr $graph / (1.0 * $num_graphs)] [expr ($graph + 1.0) / (1.0 * $num_graphs)] 0 auto $TotalData(recipoktime) $index "ms/recipok" $graph "#000000" 1]
	incr graph
	set h [human_number [expr $recipokspersec_total * 3600]]
	set d [human_number [expr $recipokspersec_total * 86400]]
	.top.recipspersectotal configure -text [format "%.2f\n%s/h\n%s/d" $recipokspersec_total $h $d]
	.top.avgreciptime configure -text [format "%.0f" $recipoktime_avg]
    } else {
	set TotalData(recipokspersec) {}
	set TotalData(recipoktime) {}
    }
    update
}

proc redraw {} {
    global Machines
    global NewStyle
    global after_token
    global Data
    global TotalData
    global DoneARedrawSinceLastUpdate

    set DoneARedrawSinceLastUpdate 1
    if {$NewStyle} {
	redraw_new_style
	return
    }

    set after_token ""
    set index 0
    set persec_total 0
    set busy_workers_total 0
    set avail_workers_total 0
    set msgs_per_sec_total 0
    set ms_per_scan_total 0
    set num_machines 0

    foreach m $Machines {
	set mach [lindex $m 0]
	if {![info exists Data($mach,busy)]} {
	    incr index
	    continue
	}
	if {$Data($mach,error)} {
	    incr index
	    continue
	}

	set busy $Data($mach,busy_snap)
	set total_workers $Data($mach,total_workers)
	set msg0 $Data($mach,persec_snap)
	set ms0 $Data($mach,time_snap)
	set persec_total [expr $persec_total + $msg0]
	# Format $busy to have as many characters as $total_workers
	set l [string length $total_workers]
	set busy [format "%${l}d" $busy]
	.top.busy$index configure -text "$busy/$total_workers"
	.top.persec$index configure -text $msg0
	.top.time$index configure -text $ms0
	if {$busy == $total_workers} {
	    .top.name$index configure -background "#CCCC00"
	} else {
	    .top.name$index configure -background "#D9D9D9"
	}

	set Data($mach,busy) [graph 0 [expr 1.0/3] 0 $Data($mach,total_workers) $Data($mach,busy) $index "Busy" 1 red 1]
	set Data($mach,persec) [graph [expr 1.0/3] [expr 2.0/3] 0 auto $Data($mach,persec) $index "Msgs/Sec" 2 green 1]
	set Data($mach,time) [graph [expr 2.0/3] 1 0 auto $Data($mach,time) $index "ms/scan" 3 blue 1]
	incr index

	if {$ms0 > 0 || $Data($mach,busy_snap) > 0 || $msg0 > 0} {
	    incr num_machines
	    incr busy_workers_total $Data($mach,busy_snap)
	    incr avail_workers_total $Data($mach,total_workers);
	    incr ms_per_scan_total $ms0
	}
    }
    lappend TotalData(busy) $busy_workers_total
    if {$num_machines > 0} {
	lappend TotalData(time) [expr 1.0 * $ms_per_scan_total / (1.0 * $num_machines)]
    } else {
	lappend TotalData(time) 0
    }
    lappend TotalData(persec) $persec_total

    incr index
    set TotalData(busy) [graph 0 [expr 1.0/3] 0 $avail_workers_total $TotalData(busy) $index "Busy" 1 red 1]
    set TotalData(persec) [graph [expr 1.0/3] [expr 2.0/3] 0 auto $TotalData(persec) $index "Msgs/Sec" 2 green 1]
    set TotalData(time) [graph [expr 2.0/3] 1 0 auto $TotalData(time) $index "ms/scan" 3 blue 1]

    set msgs_per_sec_total $persec_total
    set hour [human_number [expr $persec_total * 3600.0]]
    set day  [human_number [expr $persec_total * 86400.0]]
    set persec_total [strip_zeros [format "%.1f" $persec_total]]
    .top.c configure -text "Total throughput $persec_total/s = $hour/hour = $day/day"
    set l [string length $avail_workers_total]
    set busy_workers_total [format "%${l}d" $busy_workers_total]
    .top.busytotal configure -text "$busy_workers_total/$avail_workers_total"
    .top.persectotal configure -text [strip_zeros [format "%.1f" $msgs_per_sec_total]]
    if {$num_machines > 0} {
	.top.avgtime configure -text [strip_zeros [format "%.0f" [expr 1.0 * $ms_per_scan_total / (1.0 * $num_machines)]]]
    } else {
	.top.avgtime configure -text "--"
    }
    update
}

proc graph { start_frac end_frac min max data index label tag fill_color line_width} {
    global NewStyleTimeInterval

    set tag "data$tag"
    set c .top.c$index
    set h [winfo height $c]
    set w [winfo width $c]
    set x0 [expr int($start_frac * $w)]
    set x1 [expr int($end_frac * $w)]
    set x0 [expr $x0 + 40]
    set x1 [expr $x1 - 5]
    set diff [expr $x1 - $x0]
    set gridline_spacing 15
    if {[llength $data] > $diff} {
	set toChop [expr [llength $data] - $diff]
	set data [lrange $data $toChop end]
    }

    set multiplier 1

    if {"$label" == "Scans/s"} {
	if {$NewStyleTimeInterval == 3600} {
	    set label "Scans/h"
	    set multiplier 3600
	} elseif {$NewStyleTimeInterval == 86400} {
	    set label "Scans/d"
	    set multiplier 86400
	}
    }
    if {"$label" == "Senderoks/s"} {
	if {$NewStyleTimeInterval == 3600} {
	    set label "Senderoks/h"
	    set multiplier 3600
	} elseif {$NewStyleTimeInterval == 86400} {
	    set label "Senderoks/d"
	    set multiplier 86400
	}
    }
    if {"$label" == "Relayoks/s"} {
	if {$NewStyleTimeInterval == 3600} {
	    set label "Relayoks/h"
	    set multiplier 3600
	} elseif {$NewStyleTimeInterval == 86400} {
	    set label "Relayoks/d"
	    set multiplier 86400
	}
    }
    if {"$label" == "Recipoks/s"} {
	if {$NewStyleTimeInterval == 3600} {
	    set label "Recipoks/h"
	    set multiplier 3600
	} elseif {$NewStyleTimeInterval == 86400} {
	    set label "Recipoks/d"
	    set multiplier 86400
	}
    }

    if {"$min" == "auto"} {
	set min [lindex $data 0]
	foreach thing $data {
	    if {$thing < $min} {set min $thing}
	}
	set min [expr $multiplier * $min]
	set min [nicenum $min 1]
    }
    if {"$max" == "auto"} {
	set max [lindex $data 0]
	foreach thing $data {
	    if {$thing > $max} {set max $thing}
	}
	set max [expr $multiplier * $max]
	set max [nicenum $max 0]
    }

    set x $x0
    $c delete withtag $tag
    set coords {}
    if {$max == $min} {
	set max [expr $max + 1.0]
    }
    set diff [expr 1.0 * ($max - $min)]
    set num_gridlines [expr int((1.0 * $h) / (1.0 * $gridline_spacing))]
    if {$num_gridlines > 10} {
	set num_gridlines 10
    }
    if {$num_gridlines < 1} {
	set num_gridlines 1
    }

    set delta [nicenum [expr $diff / $num_gridlines] 1]
    foreach point $data {
	set y [expr $point * $multiplier - $min]
	set y [expr (1.0 * $y * $h) / (1.0 * $diff)]
	set y [expr $h - $y]
	if {$y < 1} {
	    set y 1
	}
	if {$y >= $h} {
	    set y [expr $h - 1]
	}
	lappend coords $x $y
	incr x
    }
    if {$delta > 0.0} {
	set last_phys_y 99999
	for {set y $min} {$y <= $max} {set y [expr $y + $delta]} {
	    set cy [expr (1.0 * ($y-$min) * $h) / (1.0 * $diff)]
	    set cy [expr $h - $cy]
	    if {$cy <= 0} {
		continue
	    }
	    if {$cy > [expr $h-1]} {
		set cy [expr $h-1]
	    }
	    if {($last_phys_y - $cy) >= (2 * $gridline_spacing)} {
		set last_phys_y $cy
		set anc w
		if {$cy < $gridline_spacing} {
		    set anc nw
		}
		if {$cy >= ($h - $gridline_spacing)} {
		    set anc sw
		}
		$c create line [expr $x0 - 10] $cy $x1 $cy -fill "#A0A0A0" -tags $tag
		$c create text [expr $x0 - 37] $cy -text [human_number $y] -tag $tag -anchor $anc
	    } else {
		$c create line $x0 $cy $x1 $cy -fill "#DDDDDD" -tags $tag
	    }
	}
    } else {
	$c create text [expr $x0 - 37] 0 -anchor nw -text [human_number $max] -tag $tag
	$c create text [expr $x0 - 37] $h -anchor sw -text [human_number $min] -tag $tag
    }
    if {[llength $coords] >= 4} {
	$c create line $coords -fill $fill_color -width $line_width -tags $tag
    }
    return $data
}
proc update_machine { line index mach } {
    if {[string match "ERROR *" $line]} {
	mach_set_status_error $mach $index $line
	return
    }
    mach_set_status_normal $mach $index ""

    mach_populate_data $mach $index $line
}

proc interactive_add_machine {} {
    set mach [.top.new get]
    if {"$mach" != ""} {
	add_machine $mach
	reconfigure
    }
}

proc reconfigure_new_style {} {
    global Machines
    global NewStyleShowScans NewStyleShowRelayoks NewStyleShowSenderoks NewStyleShowRecipoks
    catch { destroy .top.name }
    catch { destroy .top.busy }
    catch { destroy .top.scanspersec }
    catch { destroy .top.scantime }
    catch { destroy .top.relayspersec }
    catch { destroy .top.relaytime }
    catch { destroy .top.senderspersec }
    catch { destroy .top.sendertime }
    catch { destroy .top.recipspersec }
    catch { destroy .top.reciptime }
    catch { destroy .top.c }

    set col 2
    set canv_width 200
    label .top.name -text "Machine Name"
    label .top.busy -text "Busy Workers   " -foreground "#A00000"
    grid .top.name -row 0 -column 0 -sticky new
    grid .top.busy -row 0 -column 1 -sticky new
    catch { destroy .top.clabels}
    canvas .top.clabels -width $canv_width -height 10 -takefocus 0 -borderwidth 0 -background #ffffff -highlightthickness 0
    if {$NewStyleShowScans} {
	incr canv_width 200
	label .top.scanspersec -text "Scans/s   " -foreground "#00A000"
	grid .top.scanspersec -row 0 -column $col -sticky new
	incr col
	label .top.scantime -text "ms/scan   " -foreground "#0000A0"
	grid .top.scantime -row 0 -column $col -sticky new
	incr col
    }
    if {$NewStyleShowRelayoks} {
	incr canv_width 200
	label .top.relayspersec -text "Relays/s   " -foreground "#808000"
	grid .top.relayspersec -row 0 -column $col -sticky new
	incr col
	label .top.relaytime -text "ms/relay   " -foreground "#008080"
	grid .top.relaytime -row 0 -column $col -sticky new
	incr col
    }
    if {$NewStyleShowSenderoks} {
	incr canv_width 200
	label .top.senderspersec -text "Senders/s   " -foreground "#808080"
	grid .top.senderspersec -row 0 -column $col -sticky new
	incr col
	label .top.sendertime -text "ms/sender   " -foreground "#800080"
	grid .top.sendertime -row 0 -column $col -sticky new
	incr col
    }
    if {$NewStyleShowRecipoks} {
	incr canv_width 200
	label .top.recipspersec -text "Recips/s   " -foreground "#008000"
	grid .top.recipspersec -row 0 -column $col -sticky new
	incr col
	label .top.reciptime -text "ms/recip   " -foreground "#000000"
	grid .top.reciptime -row 0 -column $col -sticky new
	incr col
    }

    grid .top.clabels -row 0 -column $col -sticky nsew
    grid rowconfigure .top 0 -weight 0
    set index 0
    foreach m $Machines {
	grid_machine_new_style $m $index
	incr index
    }

    # If a machine has been deleted, destroy its windows
    catch { destroy .top.name$index }
    catch { destroy .top.busy$index }
    catch { destroy .top.scanspersec$index }
    catch { destroy .top.scantime$index }
    catch { destroy .top.relayspersec$index }
    catch { destroy .top.relaytime$index }
    catch { destroy .top.senderspersec$index }
    catch { destroy .top.sendertime$index }
    catch { destroy .top.recipspersec$index }
    catch { destroy .top.reciptime$index }
    catch { destroy .top.c$index }

    # Bottom row of labels
    catch { destroy .top.totalrow }
    catch { destroy .top.busytotal }
    catch { destroy .top.scanspersectotal }
    catch { destroy .top.avgscantime }
    catch { destroy .top.relayspersectotal }
    catch { destroy .top.avgrelaytime }
    catch { destroy .top.senderspersectotal }
    catch { destroy .top.avgsendertime }
    catch { destroy .top.recipspersectotal }
    catch { destroy .top.avgreciptime }

    # Mop up total window if a machine has been deleted
    set row [expr $index + 1]
    catch { destroy .top.c$row }

    set col 2
    label .top.totalrow -text "Totals:"
    label .top.busytotal -foreground "#A00000"
    grid .top.totalrow -row $row -column 0 -sticky new
    grid .top.busytotal -row $row -column 1 -sticky new
    if {$NewStyleShowScans} {
	label .top.scanspersectotal -foreground "#00A000"
	grid .top.scanspersectotal -row $row -column $col -sticky new
	incr col
	label .top.avgscantime -foreground "#0000A0"
	grid .top.avgscantime -row $row -column $col -sticky new
	incr col
    }
    if {$NewStyleShowRelayoks} {
	label .top.relayspersectotal -foreground "#808000"
	grid .top.relayspersectotal -row $row -column $col -sticky new
	incr col
	label .top.avgrelaytime -foreground "#008080"
	grid .top.avgrelaytime -row $row -column $col -sticky new
	incr col
    }
    if {$NewStyleShowSenderoks} {
	label .top.senderspersectotal -foreground "#808080"
	grid .top.senderspersectotal -row $row -column $col -sticky new
	incr col
	label .top.avgsendertime -foreground "#800080"
	grid .top.avgsendertime -row $row -column $col -sticky new
	incr col
    }
    if {$NewStyleShowRecipoks} {
	label .top.recipspersectotal -foreground "#008000"
	grid .top.recipspersectotal -row $row -column $col -sticky new
	incr col
	label .top.avgreciptime -foreground "#000000"
	grid .top.avgreciptime -row $row -column $col -sticky new
	incr col
    }
    set num_items [expr $col-1]

    canvas .top.c$index -width $canv_width -height 60 -takefocus 0 -borderwidth 0 -background #FFFFEE -highlightthickness 0
    grid .top.c$index -row $row -column $col -sticky nsew -pady 1
    grid rowconfigure .top $row -weight 3

    for {set i 0} {$i < $col} {incr i} {
	grid columnconfigure .top $i -weight 0
    }
    grid columnconfigure .top $col -weight 1

    incr index
    incr row
    # Now a spot for adding a new machine...
    catch { destroy .top.newlab }
    catch { destroy .top.new }
    catch { destroy .top.all }

    label .top.newlab -text "Add Machine: "
    entry .top.new -width 20
    grid .top.newlab -row $row -column 0
    grid .top.new -row $row -column 1 -columnspan [expr $col - 1] -sticky ew
    bind .top.new <Return> interactive_add_machine
    button .top.all -text "Summary" -command all_or_summary
    grid .top.all -row $row -column [expr $col] -sticky w
    grid rowconfigure .top $row -weight 0

    wm deiconify .top
}

proc all_or_summary {} {
    set text [.top.all cget -text]
    set win [get_machine_windows]
    set rowcol [grid size .top]
    set rows [lindex $rowcol 1]

    if {"$text" == "Summary"} {
	.top.all configure -text "All"
	foreach w $win {
	    grid remove $w
	}
	for {set i 1} {$i < [expr $rows - 2]} {incr i} {
	    grid rowconfigure .top $i -weight 0
	}
    } else {
	.top.all configure -text "Summary"
	foreach w $win {
	    grid $w
	}
	for {set i 1} {$i < [expr $rows - 2]} {incr i} {
	    grid rowconfigure .top $i -weight 1
	}
    }

    # Cancel any user-specified geometry
    wm geometry .top ""
}

proc reconfigure {} {
    global Machines
    global NewStyle
    if {$NewStyle} {
	reconfigure_new_style
	return
    }

    set index 0
    foreach m $Machines {
	grid_machine $m $index
	incr index
    }

    # Top row of labels
    catch { destroy .top.busy }
    catch { destroy .top.persec }
    catch { destroy .top.time }
    catch { destroy .top.c }
    catch { destroy .top.name }

    label .top.name -text "Machine Name"
    label .top.busy -text "Busy Workers" -foreground "#A00000"
    label .top.persec -text "Msgs/s" -foreground "#00A000"
    label .top.time -text " ms/scan " -foreground "#0000A0"
    label .top.c -text ""
    grid .top.name -row 0 -column 0 -sticky new
    grid .top.busy -row 0 -column 1 -sticky new
    grid .top.persec -row 0 -column 2 -sticky new
    grid .top.time -row 0 -column 3 -sticky new
    grid .top.c -row 0 -column 4 -sticky new

    grid rowconfigure .top 0 -weight 0
    # If a machine has been deleted, destroy its windows
    catch { destroy .top.name$index}
    catch { destroy .top.busy$index}
    catch { destroy .top.persec$index}
    catch { destroy .top.time$index}
    catch { destroy .top.c$index}

    incr index
    # Bottom row of labels
    catch { destroy .top.busytotal }
    catch { destroy .top.persectotal }
    catch { destroy .top.avgtime }
    catch { destroy .top.totalrow }
    catch { destroy .top.c$index }

    # Mop up total window if a machine has been deleted
    set i [expr $index + 1]
    catch { destroy .top.c$i }

    label .top.totalrow -text "Totals:"
    label .top.busytotal
    label .top.persectotal
    label .top.avgtime
    canvas .top.c$index -width 400 -height 60 -takefocus 0 -borderwidth 0 -background #FFFFF0 -highlightthickness 0

    grid .top.totalrow -row $index -column 0 -sticky new
    grid .top.busytotal -row $index -column 1 -sticky new
    grid .top.persectotal -row $index -column 2 -sticky new
    grid .top.avgtime -row $index -column 3 -sticky new
    grid .top.c$index -row $index -column 4 -sticky nsew -pady 1
    grid rowconfigure .top $index -weight 3
    incr index
    # Now a spot for adding a new machine...
    catch { destroy .top.newlab }
    catch { destroy .top.new }

    label .top.newlab -text "Add Machine: "
    entry .top.new -width 20
    grid .top.newlab -row $index -column 0
    grid .top.new -row $index -column 1 -columnspan 3 -sticky ew
    bind .top.new <Return> interactive_add_machine
    button .top.all -text "Summary" -command all_or_summary
    grid .top.all -row $index -column 4 -sticky w
    grid rowconfigure .top $index -weight 0

    grid columnconfigure .top 0 -weight 0
    grid columnconfigure .top 1 -weight 0
    grid columnconfigure .top 2 -weight 0
    grid columnconfigure .top 3 -weight 0
    grid columnconfigure .top 4 -weight 1
    wm deiconify .top
}

proc busyworkers { mach } {
    global ctr
    global Data
    incr ctr
    set w .workers$ctr
    catch { destroy $w }
    toplevel $w
    wm title $w "Busy workers: $mach"
    wm iconname $w "$mach workers"
    set Data($mach,busyworkerwin) $w

    # Open a new SSH connection for the busyworkers info
    global SSHCommand
    global MD_MX_CTRL
    set hmach [host_plus_user $mach]
    set fp [open "| $SSHCommand $hmach $MD_MX_CTRL" "r+"]
    fconfigure $fp -blocking 0
    fileevent $fp readable [list busyworkers_readable $mach $fp]

    tickle_busyworkers $mach $fp

    text $w.t -width 80 -height 35
    pack $w.t -side left -expand 1 -fill both
    $w.t tag bind pid <Enter> [list enter_pid $w.t]
    $w.t tag bind pid <Leave> [list leave_pid $w.t]
    $w.t tag bind pid <ButtonPress-1> [list trace_worker $w.t $mach]
}

proc tickle_busyworkers { mach fp } {
    global Data

    catch {
	set Data($mach,busydata) ""
	# We have to use the old command for backware-compatibility.
	puts $fp "busyslaves\nfoo_no_such_command"
	flush $fp
    }
}

proc busyworkers_readable { mach fp } {
    global Data

    gets $fp line
    if {"$line" == ""} {
	if {[eof $fp]} {
	    close $fp
	    catch { destroy $Data($mach,busyworkerwin) }
	}
	return
    }
    if {"$line" != "error: Unknown command"} {
	lappend Data($mach,busydata) $line
	return
    }
    update_busyworkers $mach $fp
    global BusyWorkerUpdateInterval
    after $BusyWorkerUpdateInterval [list tickle_busyworkers $mach $fp]
}
proc trace_worker { w mach } {
    global TraceCommand
    set tags [$w tag names current]
    set index [lsearch -glob $tags "Z*"]
    if {$index >= 0} {
	set tag [lindex $tags $index]
	set pid [string range $tag 1 end]
	ssh $mach "$TraceCommand $pid" "Process $pid on $mach"
    }
}
proc enter_pid { w } {
    set tags [$w tag names current]
    set index [lsearch -glob $tags "Z*"]
    if {$index >= 0} {
	set tag [lindex $tags $index]
	$w tag configure $tag -foreground "#A00000"
    }
}

proc leave_pid { w } {
    set tags [$w tag names current]
    set index [lsearch -glob $tags "Z*"]
    if {$index >= 0} {
	set tag [lindex $tags $index]
	$w tag configure $tag -foreground "#000000"
    }
}

proc compare_workers { a b } {
    set acmd [lindex $a 3]
    set bcmd [lindex $b 3]
    set x [string compare $bcmd $acmd]
    if {$x != 0} {
	return $x
    }

    set an [lindex $a 0]
    set bn [lindex $b 0]

    set aago [lindex $a 5]
    set bago [lindex $b 5]
    if {[string match "ago=*" $aago] && [string match "ago=*" $bago]} {
	set aago [string range $aago 4 end]
	set bago [string range $bago 4 end]
	set x [expr $bago - $aago]
	if {$x != 0} {
	    return $x
	}
    }

    return [expr $an - $bn]
}

proc update_busyworkers { mach fp} {
    global Data
    set w $Data($mach,busyworkerwin)
    if {![winfo exists $w]} {
	catch { close $fp }
	return
    }
    $w.t configure -state normal
    $w.t delete 1.0 end

    # Clear out tags
    foreach tag [$w.t tag names] {
	if {"$tag" != "pid"} {
	    $w.t tag delete $tag
	}
    }

    set busyguys [lsort -command compare_workers $Data($mach,busydata)]

    set count(scan) 0
    set count(relayok) 0
    set count(senderok) 0
    set count(recipok) 0

    foreach line $busyguys {
	set lst [split $line]
	set workerno [lindex $lst 0]
	set pid [lindex $lst 2]
	set cmd [lindex $lst 3]
	incr count($cmd)
	set len [string length "$workerno B $pid "]
	set line [string range $line $len end]
	$w.t insert end [format "%4d" $workerno] workerno
	$w.t insert end " "
	$w.t tag delete "Z$pid"
	$w.t insert end [format "%6d" $pid] [list pid "Z$pid"]
	$w.t insert end " $line\n"

    }

    set title "Busy workers: $mach"
    foreach cmd {scan relayok senderok recipok} {
	if {$count($cmd) > 0} {
	    set c $count($cmd)
	    append title " $cmd=$c"
	}
    }
    wm title $w $title
}

proc popup_machine_menu { m index x y} {
    catch { destroy .m }
    menu .m -tearoff 0
    .m add command -label "SSH" -command [list ssh $m]
    .m add command -label "Busy Workers" -command [list busyworkers $m]
    .m add separator
    .m add command -label "Delete" -command [list del_machine $m]
    tk_popup .m $x $y
}

proc grid_machine_new_style { m index } {
    global NewStyleShowScans NewStyleShowRelayoks NewStyleShowSenderoks NewStyleShowRecipoks
    set m [lindex $m 0]

    set disp_m $m
    if {[regexp {@(.*)$} $m foo host]} {
	set disp_m $host
    }

    # Chop off domain name from host
    if {[regexp {^([^.]+)\.} $disp_m foo new_m]} {
	set disp_m $new_m
    }
    set row [expr $index + 1]
    catch { destroy .top.name$index }
    catch { destroy .top.busy$index }
    catch { destroy .top.scanspersec$index }
    catch { destroy .top.scantime$index }
    catch { destroy .top.relayspersec$index }
    catch { destroy .top.relaytime$index }
    catch { destroy .top.senderspersec$index }
    catch { destroy .top.sendertime$index }
    catch { destroy .top.recipspersec$index }
    catch { destroy .top.reciptime$index }
    catch { destroy .top.c$index }

    set column 2
    set canv_width 200
    label .top.name$index -text $disp_m -relief raised
    bind .top.name$index <ButtonPress-1> [list popup_machine_menu $m $index %X %Y]
    bind .top.name$index <ButtonPress-2> [list popup_machine_menu $m $index %X %Y]
    bind .top.name$index <ButtonPress-3> [list popup_machine_menu $m $index %X %Y]
    label .top.busy$index -text "" -foreground "#A00000"
    grid .top.name$index -row $row -column 0 -sticky new
    grid .top.busy$index -row $row -column 1 -sticky new

    if {$NewStyleShowScans} {
	label .top.scanspersec$index -foreground "#00A000"
	grid .top.scanspersec$index -row $row -column $column -sticky new
	incr column
	label .top.scantime$index -foreground "#0000A0"
	grid .top.scantime$index -row $row -column $column -sticky new
	incr column
	incr canv_width 200
    }
    if {$NewStyleShowRelayoks} {
	label .top.relayspersec$index -foreground "#808000"
	grid .top.relayspersec$index -row $row -column $column -sticky new
	incr column
	label .top.relaytime$index -foreground "#008080"
	grid .top.relaytime$index -row $row -column $column -sticky new
	incr column
	incr canv_width 200
    }
    if {$NewStyleShowSenderoks} {
	label .top.senderspersec$index -foreground "#808080"
	grid .top.senderspersec$index -row $row -column $column -sticky new
	incr column
	label .top.sendertime$index -foreground "#800080"
	grid .top.sendertime$index -row $row -column $column -sticky new
	incr column
	incr canv_width 200
    }
    if {$NewStyleShowRecipoks} {
	label .top.recipspersec$index -foreground "#008000"
	grid .top.recipspersec$index -row $row -column $column -sticky new
	incr column
	label .top.reciptime$index -foreground "#000000"
	grid .top.reciptime$index -row $row -column $column -sticky new
	incr column
	incr canv_width 200
    }
    canvas .top.c$index -width $canv_width -height 60 -takefocus 0 -borderwidth 0 -background #FFFFFF -highlightthickness 0
    grid .top.c$index -row $row -column $column -sticky nsew -pady 1
    grid rowconfigure .top $row -weight 1
}
proc grid_machine { m index } {
    set m [lindex $m 0]
    set row [expr $index + 1]

    catch { destroy .top.name$index}
    catch { destroy .top.busy$index}
    catch { destroy .top.persec$index}
    catch { destroy .top.time$index}
    catch { destroy .top.c$index}

    set disp_m $m
    if {[regexp {@(.*)$} $m foo host]} {
	set disp_m $host
    }

    label .top.name$index -text $disp_m -relief raised
    bind .top.name$index <ButtonPress-1> [list popup_machine_menu $m $index %X %Y]
    bind .top.name$index <ButtonPress-2> [list popup_machine_menu $m $index %X %Y]
    bind .top.name$index <ButtonPress-3> [list popup_machine_menu $m $index %X %Y]
    label .top.busy$index -text ""
    label .top.persec$index -text ""
    label .top.time$index -text ""
    canvas .top.c$index -width 600 -height 60 -takefocus 0 -borderwidth 0 -background white -highlightthickness 0
    .top.c$index create text 2 2 -anchor nw -text "" -tags statusText
    grid .top.name$index -row $row -column 0 -sticky new
    grid .top.busy$index -row $row -column 1 -sticky new
    grid .top.persec$index -row $row -column 2 -sticky new
    grid .top.time$index -row $row -column 3 -sticky new
    grid .top.c$index -row $row -column 4 -sticky nsew -pady 1
    grid rowconfigure .top $row -weight 1

}

proc kick_off_update {} {
    global Machines
    global NewStyle
    global DoneARedrawSinceLastUpdate
    global MachinesAwaitingReply
    global MainUpdateInterval

    if {$DoneARedrawSinceLastUpdate} {
	set DoneARedrawSinceLastUpdate 0
	if {$NewStyle} {
	    set cmd "rawload1 60"
	} else {
	    set cmd "rawload"
	}

	set MachinesAwaitingReply {}
	foreach m $Machines {
	    catch {
		set fp [lindex $m 1]
		puts $fp $cmd
		flush $fp
		lappend MachinesAwaitingReply [lindex $m 0]
	    }
	}
    }
    after $MainUpdateInterval kick_off_update
}

## translated from C-code in Blt, who got it from:
##      Taken from Paul Heckbert's "Nice Numbers for Graph Labels" in
##      Graphics Gems (pp 61-63).  Finds a "nice" number approximately
##      equal to x.
proc nicenum {x floor} {

    if {$x == 0} {
	return 0
    }

    set negative 0

    if {$x < 0} {
        set x [expr -$x]
        set negative 1
    }

    set exponX [expr floor(log10($x))]
    set fractX [expr $x/pow(10,$exponX)]; # between 1 and 10
    if {$floor} {
        if {$fractX < 2.0} {
            set nf 1.0
	} elseif {$fractX < 3.0} {
	    set nf 2.0
	} elseif {$fractX < 4.0} {
	    set nf 3.0
	} elseif {$fractX < 5.0} {
            set nf 4.0
        } elseif {$fractX < 10.0} {
            set nf 5.0
        } else {
	    set nf 10.0
        }
    } elseif {$fractX <= 1.0} {
        set nf 1.0
    } elseif {$fractX <= 1.5} {
	set nf 1.5
    } elseif {$fractX <= 2.0} {
        set nf 2.0
    } elseif {$fractX <= 2.5} {
        set nf 2.5
    } elseif {$fractX <= 3.0} {
	set nf 3.0
    } elseif {$fractX <= 4.0} {
	set nf 4.0
    } elseif {$fractX <= 5.0} {
        set nf 5.0
    } elseif {$fractX <= 6.0} {
        set nf 6.0
    } elseif {$fractX <= 8.0} {
        set nf 8.0
    } else {
        set nf 10.0
    }
    if { $negative } {
        return [expr -$nf * pow(10,$exponX)]
    } else {
	set value [expr $nf * pow(10,$exponX)]
	return $value
    }
}

proc human_number { num } {
    if {$num <= 1000} {
	return [strip_zeros [format "%.1f" $num]]
    }
    set num [expr $num / 1000.0]
    if {$num <= 1000} {
	set num [strip_zeros [format "%.1f" $num]]
	return "${num}K"
    }
    set num [expr $num / 1000.0]
    if {$num <= 1000} {
	set num [strip_zeros [format "%.1f" $num]]
	return "${num}M"
    }
    set num [expr $num / 1000.0]
    set num [strip_zeros [format "%.1f" $num]]
    return "${num}G"
}

proc pick_color { host } {
    set color 0
    set components {AA BB CC EE}

    catch { set host [lindex $host end] }
    set host [split $host ""]
    foreach char $host {
	set color [expr $color + 1]
	binary scan $char "c" x
	incr color $x
	if { $color <= 0 } {
	    set color [expr $x + 1]
	}
    }
    set ans "#"
    expr srand($color)
    for {set i 0} {$i < 3} {incr i} {
	set off [expr int(4.0 * rand())]
	append ans [lindex $components $off]
    }
    return $ans
}

proc ssh { host {cmd ""} {title ""}} {
    set color [pick_color $host]
    if {"$title" == ""} {
	set title "SSH $host"
    }
    global SSHCommand
    set hmach [host_plus_user $host]
    exec xterm -hold -title $title -bg #000000 -fg $color -e $SSHCommand $hmach $cmd &
}

wm withdraw .
foreach mach $argv {
    if {"$mach" == "-archive"} {
	set DoArchive 1
	continue
    }
    if {"$mach" == "-d"} {
	set NewStyleTimeInterval 86400
	continue
    }
    if {"$mach" == "-h"} {
	set NewStyleTimeInterval 3600
	continue
    }

    if {"$mach" == "-n"} {
	set NewStyle 1
	set NewStyleShowScans 1
	continue
    }
    if {"$mach" == "-r"} {
	set NewStyle 1
	set NewStyleShowRelayoks 1
	continue
    }
    if {"$mach" == "-s"} {
	set NewStyle 1
	set NewStyleShowSenderoks 1
	continue
    }
    if {"$mach" == "-t"} {
	set NewStyle 1
	set NewStyleShowRecipoks 1
	continue
    }
    add_machine $mach
}

catch { destroy .top}
toplevel .top
wm title .top "Watch Multiple MIMEDefangs"
wm iconname .top "MIMEDefangs"
wm withdraw .top
reconfigure
wm deiconify .top
update
kick_off_update
tkwait window .top
exit
