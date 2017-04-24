#!/usr/bin/env python
import operator
import sys, os
from subprocess import call

def printArr(arr, time, file):
	file.write("{}".format(time))
	for x in arr:
		file.write(" {}".format(x))
	file.write("\n")


def printSLine(line, time, file):
	file.write("{} {}\n".format(time, line))


def calcHitRatio(a,b):
	try:
		x = a*10000/b
	except:
		return 0
	x = 10000 - x;
	x = x * 1.0
	return x/100.0

Topology = "AS"
os.system("rm -rf *"+Topology+"*/*/*RR*")
os.system("rm -rf *"+Topology+"*/*/*HR*")
os.system("ls *"+Topology+"*/*/*Cache* > files.txt")
files = open('files.txt').readlines()

numberOfRouters = 79

for f in files:
	routersHRFile = open(f[0:-1] + '-RoutersHR', 'w')
	routersRRFile = open(f[0:-1] + '-RoutersRR', 'w')
	globalHRFile = open(f[0:-1] + '-GlobalHR', 'w')
	globalRRFile = open(f[0:-1] + '-GlobalRR', 'w')
	global_requests = 0
	global_misses = 0
	routersHR = [0] * numberOfRouters
	routersRR = [0] * numberOfRouters

	x = open(f[0:-1]).readlines()[1:]
	last = '2000'
	pattern = [dict()] * numberOfRouters

	for line in x:
		line = line.split()
		if len(line)<4:
			break;
		if line[0] != last:
			
			printArr(routersHR, last, routersHRFile)
			printArr(routersRR, last, routersRRFile)
			printSLine(calcHitRatio(global_misses, global_requests), last, globalHRFile)
			printSLine(global_requests, last, globalRRFile)

			global_requests = 0
			global_misses = 0
			last = line[0]
		# if line[2]=='HR':
		# 	try:
		# 		routersHR[int(line[1])] = float(line[3][0:-1])
		# 	except:
		# 		routersHR[int(line[1])] = 0
		# elif line[1][0]!='m'&& !line[2] =='RR':
		# 	routersRR[int(line[1])] = int(line[3])
		# elif line[2][0]=='/':
		# 	pattern[int(line[1])][line[2]] = int(line[3])
		if line[1][0]=='c':
			global_requests += int(line[3])
		elif line[1][0]=='s':
			global_misses += int(line[3])

	printArr(routersHR, last, routersHRFile)
	printArr(routersRR, last, routersRRFile)
	printSLine(calcHitRatio(global_misses, global_requests), last, globalHRFile)
	printSLine(global_requests, last, globalRRFile)

	global_requests = 0
	global_misses = 0
	last = line[0]