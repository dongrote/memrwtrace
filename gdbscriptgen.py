#!/usr/bin/env python
import sys
import json

rs_num_to_string = [
        '$zero',
        '$at',
        '$v0',
        '$v1',
        '$a0',
        '$a1',
        '$a2',
        '$a3',
        '$t0',
        '$t1',
        '$t2',
        '$t3',
        '$t4',
        '$t5',
        '$t6',
        '$t7',
        '$s0',
        '$s1',
        '$s2',
        '$s3',
        '$s4',
        '$s5',
        '$s6',
        '$s7',
        '$t8',
        '$t9',
        '$k0',
        '$k1',
        '$gp',
        '$sp',
        '$s8',
        '$fp',
        '$ra']


line = sys.stdin.read()
mydict = json.loads(line)
print 'set pagination off'
print 'set logging file memrwtrace.out'
print 'set logging on'
for instruction in mydict:
    print 'b *%d' % instruction['address']
    print 'commands'
    print 'x/1i $pc'
    print 'print %d+%s' % (instruction['immediate'],rs_num_to_string[instruction['rs']])
    print 'c'
    print 'end'
print 'r'
print 'quit'
