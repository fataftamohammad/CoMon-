#!/usr/bin/env python2
# encoding: utf-8

import logging
import sys

from eval import read, get_experiments, get_overhead_size, get_overhead_msgs, get_pit_usage, get_real_satisfaction_ratio, get_avg_signal_over_time
from plot import plot_over_time

OUTPUT_DIR = 'plots/attack_random_prefixes/'


def main():
    db = None
    if(len(sys.argv) > 1 and sys.argv[1]):
        # read db
        logging.info("Reading output directory to database.")
        db = read(sys.argv[1])
    else:
        sys.exit()

    legend = ['detection']
    experiments = get_experiments(db, mar=2, ftbm=1)
    exp_name = 'attack_random_prefixes'

    plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                   xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                   filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
    plot_over_time(get_overhead_size(db, experiments, legend),
                   xlabel='Time [s]', ylabel='Overhead',
                   filename=exp_name + '_overhead', output_dir=OUTPUT_DIR)
    plot_over_time(get_overhead_size(db, experiments, legend, received=False),
                   xlabel='Time [s]', ylabel='Overhead (sent)',
                   filename=exp_name + '_overhead_sent', output_dir=OUTPUT_DIR)
    plot_over_time(get_overhead_size(db, experiments, legend, sent=False),
                   xlabel='Time [s]', ylabel='Overhead (received)',
                   filename=exp_name + '_overhead_received', output_dir=OUTPUT_DIR)
    plot_over_time(get_overhead_msgs(db, experiments, legend, received=False),
                   xlabel='Time [s]', ylabel='# Overhead (sent)',
                   filename=exp_name + '_#overhead_sent', output_dir=OUTPUT_DIR)
    plot_over_time(get_overhead_msgs(db, experiments, legend, sent=False),
                   xlabel='Time [s]', ylabel='# Overhead (received)',
                   filename=exp_name + '_#overhead_received', output_dir=OUTPUT_DIR)
    plot_over_time(get_pit_usage(db, experiments, legend),
                   xlabel='Time [s]', ylabel='PIT Usage',
                   filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
    plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                   xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                   filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
    plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                   xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                   filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

if __name__ == '__main__':
    main()
