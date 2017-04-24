#!/usr/bin/env python2
# encoding: utf-8

from __future__ import division
import logging
import sys

from eval import read, get_experiments, get_overhead_size, get_overhead_msgs, get_pit_usage, get_real_satisfaction_ratio, get_avg_signal_over_time
from plot import plot_over_time

OUTPUT_DIR = 'plots/other_topo/'


def main():
    db = None
    if(len(sys.argv) > 1 and sys.argv[1]):
        # read from db
        logging.info("Reading output directory to database.")
        db = read(sys.argv[1])
    else:
        # read pickled
        logging.info("Using pickled data.")
        # db = DummyDB()
    legend = ['detection']

    for topo, num_attackers, num_monitors in [('xw1239.txt', 55, 32),
                                              ('xw1755.txt', 15, 9),
                                              ('xw3257.txt', 28, 17)]:

        #
        # No cache
        #

        cachesize = 0

        # AS - MAR0
        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar0_25%_attackers@500_cache=0'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=1000)
        exp_name = '{}_mar0_25%_attackers@1000_cache=0'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=10000)
        exp_name = '{}_mar0_25%_attackers@10000_cache=0'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        # # AS - MAR1
        experiments = get_experiments(db, topo=topo, mar=1,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar1_25%_attackers@500_cache=0'.format(topo)

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

        # AS - MAR2
        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar2_25%_attackers@500_cache=0'.format(topo)

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
                       xlabel='time [s]', ylabel='average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='time [s]', ylabel='average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=1000)
        exp_name = '{}_mar2_25%_attackers@1000_cache=0'.format(topo)

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
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=10000)
        exp_name = '{}_mar2_25%_attackers@10000_cache=0'.format(topo)

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
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='time [s]', ylabel='average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='time [s]', ylabel='average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        #
        # cache = 500
        #

        cachesize = 500

        # AS - MAR0
        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar0_25%_attackers@500_cache=500'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=1000)
        exp_name = '{}_mar0_25%_attackers@1000_cache=500'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=0,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=10000)
        exp_name = '{}_mar0_25%_attackers@10000_cache=500'.format(topo)

        plot_over_time(get_real_satisfaction_ratio(db, experiments, legend, nodes='client'),
                       xlabel='Time [s]', ylabel='Global Satisfaction Ratio (Legitimate Interests)',
                       filename=exp_name + '_global_satisfaction_legitimate', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        # # AS - MAR1
        experiments = get_experiments(db, topo=topo, mar=1,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar1_25%_attackers@500_cache=500'.format(topo)

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

        # AS - MAR2
        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=500)
        exp_name = '{}_mar2_25%_attackers@500_cache=500'.format(topo)

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
                       xlabel='time [s]', ylabel='average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='time [s]', ylabel='average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=1000)
        exp_name = '{}_mar2_25%_attackers@1000_cache=500'.format(topo)

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
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='Time [s]', ylabel='Average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

        experiments = get_experiments(db, topo=topo, mar=2,
                                      cachesize=cachesize, numAttackers=num_attackers, numMonitors=num_monitors,
                                      attackersFrequency=10000)
        exp_name = '{}_mar2_25%_attackers@10000_cache=500'.format(topo)

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
        plot_over_time(get_pit_usage(db, experiments, legend),
                       xlabel='Time [s]', ylabel='PIT Usage',
                       filename=exp_name + '_pit_usage', percent=True, output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'EntriesSatisfiedBefore', legend),
                       xlabel='time [s]', ylabel='average entries in list "satisfied before"',
                       filename=exp_name + '_entries_satisfied_before', output_dir=OUTPUT_DIR)
        plot_over_time(get_avg_signal_over_time(db, experiments, 'MaliciousRequestedMulti', legend),
                       xlabel='time [s]', ylabel='average entries in list "malicious names requested before"',
                       filename=exp_name + '_entries_malicious_requested_before', output_dir=OUTPUT_DIR)

if __name__ == '__main__':
    main()
