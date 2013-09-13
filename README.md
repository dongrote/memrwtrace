memrwtrace
==========

Here's the basic gist:
 - Build memrwtrace.c on a mipsbe machine (gcc -o memrwtrace memrwtrace.c)
 - Run memrwtrace against any ELF on the system, pipe the output in the
   gdbgenscript.py Python script, direct _that_ output into a file like script.gdb
 - Run the analyzed ELF file in gdb, passing in the generated gdb script

 - ./memrwtrace $elffile 2>/dev/null | ./gdbgenscript.py > script.gdb && gdb -x script.gdb $elffile

 - The resulting file (memrwtrace.out) will have all of the memory addresses that are
   either read or written
 - Output includes the original instruction so you can determine whether the
   operation was a read or a write.
 - I'll work on making the output easier to parse, but I have to leave now.
