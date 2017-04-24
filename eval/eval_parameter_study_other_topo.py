#!/usr/bin/env python2
# encoding: utf-8

from __future__ import division
import logging
import sys

from eval import read, get_experiments, get_overhead_size, get_overhead_msgs, get_pit_usage, get_real_satisfaction_ratio, get_avg_signal_over_time
from plot import plot_over_time

OUTPUT_DIR = 'plots/parameter_study_other_topo/xw3257'


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

    default_observation_period = 10
    default_cachesize = 0
    default_attackers_frequency = 1000
    default_client_frequency = 100
    default_tau = 0.1
    default_gamma = 0.5
    default_pit_lifetime = 2
    default_pit_size = 5000
    default_payload_size = 1100

    legend = ['observationPeriod']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'observation_period'
    plot(db, experiments, exp_name, legend)

    legend = ['tau']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'tau'
    plot(db, experiments, exp_name, legend)

    legend = ['gamma']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'gamma'
    plot(db, experiments, exp_name, legend)

    legend = ['pitLifetime']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'pit_lifetime'
    plot(db, experiments, exp_name, legend)

    legend = ['pitSize']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  payloadSize=default_payload_size)
    exp_name = 'pit_size'
    plot(db, experiments, exp_name, legend)

    legend = ['clientFrequency']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'client_frequency'
    plot(db, experiments, exp_name, legend)

    legend = ['payloadSize']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size)
    exp_name = 'payload_size'
    plot(db, experiments, exp_name, legend)

    legend = ['attackersFrequency']
    experiments = get_experiments(db, cachesize=default_cachesize,
                                  observationPeriod=default_observation_period,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'attackers_frequency'
    plot(db, experiments, exp_name, legend)

    legend = ['cacheSize']
    experiments = get_experiments(db, observationPeriod=default_observation_period,
                                  attackersFrequency=default_attackers_frequency,
                                  clientFrequency=default_client_frequency,
                                  tau=default_tau,
                                  gamma=default_gamma,
                                  pitLifetime=default_pit_lifetime,
                                  pitSize=default_pit_size,
                                  payloadSize=default_payload_size)
    exp_name = 'cacheSize'
    plot(db, experiments, exp_name, legend)


def plot(db, experiments, exp_name, legend):
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
