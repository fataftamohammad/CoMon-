#!/usr/bin/env python
# encoding: utf-8

import sys


def get_sat_ratio(filename, nodes):
    satisfied = 0
    timedout = 0
    with open(filename, 'r') as f:
        for line in f.readlines():
            if line.count(nodes) > 0:
                if line.count('SatisfiedInterests') > 0:
                    splitted = line.split()
                    if int(splitted[0]) >= 60 and int(splitted[0]) < 360:
                        satisfied += int(splitted[5])
                elif line.count('TimedOutInterests') > 0:
                    splitted = line.split()
                    if int(splitted[0]) >= 60 and int(splitted[0]) < 360:
                        timedout += int(splitted[5])

        return satisfied / (satisfied + timedout)


def main():
    if(len(sys.argv) > 1 and sys.argv[1]):
        print('Legit: ', get_sat_ratio(sys.argv[1], 'client'))
        print('Illegit: ', get_sat_ratio(sys.argv[1], 'attacker'))
        print('All: ', get_sat_ratio(sys.argv[1], ''))

if __name__ == '__main__':
    main()
