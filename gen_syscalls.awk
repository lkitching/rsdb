BEGIN { print "syscalls![" }
/__NR_/ { gsub(/__NR_/, "", $2); print "  call(" $2 "," $3 ")," }
END { print "];" }
