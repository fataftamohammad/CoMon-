#!/usr/bin/env python2
# encoding: utf-8

from __future__ import division
import logging
import sys

from eval import read, get_experiments, get_real_satisfaction_ratio, get_pit_usage
from plot import plot_over_time

OUTPUT_DIR = 'plots/cawka-xw3257/'


def main():
    db = None
    if(len(sys.argv) > 1 and sys.argv[1]):
        # read from db
        logging.info("Reading output directory to database.")
        db = read(sys.argv[1])

        avg(db)
        individual_runs(db)
    else:
        sys.exit()


def avg(db):
    legend = ['detection', 'attackersFrequency']

    experiments = get_experiments(db, tau=0)

    exp_name = 'cawka'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='good-leaf'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)

    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)


def individual_runs(db):
    output_dir = 'plots/xw3257-individual-runs/'
    legend = ['detection', 'attackersFrequency']

    for i in range(1, 42):
        experiment = get_experiments(db, id=i)
        exp_name = 'cawka-%d' % i
        plot_over_time(get_real_satisfaction_ratio(db, experiment, legend, nodes='good-leaf'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=output_dir)

        plot_over_time(get_pit_usage(db, experiment, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=output_dir)

if __name__ == '__main__':
    main()
