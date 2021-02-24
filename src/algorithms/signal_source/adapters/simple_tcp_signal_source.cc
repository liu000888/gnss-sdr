/*!
 * \file simple_tcp_signal_source.cc
 * \brief Receives ip frames containing samples in TCP frame encapsulation
 * using a high performance packet capture library (libpcap)
 * \author Liu work on Javier Arribas jarribas (at) cttc.es
 * -----------------------------------------------------------------------------
 *
 * Copyright (C) 2010-2020  (see AUTHORS file for a list of contributors)
 *
 * GNSS-SDR is a software defined Global Navigation
 *          Satellite Systems receiver
 *
 * This file is part of GNSS-SDR.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * -----------------------------------------------------------------------------
 */


#include "simple_tcp_signal_source.h"
#include "configuration_interface.h"
#include <glog/logging.h>
#include <iostream>


SimpleTcpSignalSource::SimpleTcpSignalSource(const ConfigurationInterface* configuration,
    const std::string& role, unsigned int in_stream, unsigned int out_stream,
    Concurrent_Queue<pmt::pmt_t>* queue __attribute__((unused))) : role_(role), in_stream_(in_stream), out_stream_(out_stream)
{
    // DUMP PARAMETERS
    const std::string default_dump_file("./data/signal_source.dat");
    const std::string default_item_type("gr_complex");
    dump_ = configuration->property(role + ".dump", false);
    dump_filename_ = configuration->property(role + ".dump_filename", default_dump_file);

    // network PARAMETERS
    const std::string default_address("127.0.0.1");
    const int default_port = 1234;
    const std::string address = configuration->property(role + ".origin_address", default_address);
    int port = configuration->property(role + ".port", default_port);

    RF_channels_ = configuration->property(role + ".RF_channels", 1);  // TODO these may be option params
    IQ_swap_ = configuration->property(role + ".IQ_swap", false);

    const std::string default_sample_type("cbyte");
    const std::string sample_type = configuration->property(role + ".sample_type", default_sample_type);
    item_type_ = configuration->property(role + ".item_type", default_item_type);
    // output item size is always gr_complex
    item_size_ = sizeof(gr_complex);

    // call a ip packet source, which are implementation of this tcp and pcap method
    tcp_gnss_rx_source_ = Gr_Complex_Simple_Tcp_Source::make(address,
        port,
        sample_type,
        item_size_,
        IQ_swap_);

    // if (channels_in_tcp_ >= RF_channels_)
    if (1)
        {
            for (int n = 0; n < channels_in_tcp_; n++)
                {
                    null_sinks_.emplace_back(gr::blocks::null_sink::make(sizeof(gr_complex)));
                }
        }
    else
        {
            std::cout << "Configuration error: RF_channels<channels_in_use\n";
            exit(0);
        }

    if (dump_)
        {
            for (int n = 0; n < channels_in_tcp_; n++)
                {
                    DLOG(INFO) << "Dumping output into file " << (dump_filename_ + "c_h" + std::to_string(n) + ".bin");
                    file_sink_.emplace_back(gr::blocks::file_sink::make(item_size_, (dump_filename_ + "_ch" + std::to_string(n) + ".bin").c_str()));
                }
        }
    if (in_stream_ > 0)
        {
            LOG(ERROR) << "A signal source does not have an input stream";
        }
    if (out_stream_ > 1)
        {
            LOG(ERROR) << "This implementation only supports one output stream";
        }
}


void SimpleTcpSignalSource::connect(gr::top_block_sptr top_block)
{
    // connect null sinks to unused streams
    // for (int n = 0; n < channels_in_tcp_; n++)
    //     {
    //         top_block->connect(tcp_gnss_rx_source_, n, null_sinks_.at(n), 0);
    //     }
    // DLOG(INFO) << "connected tcp_source to null_sinks to enable the use of spare channels\n";

    if (dump_)
        {
            for (int n = 0; n < channels_in_tcp_; n++)
                {
                    top_block->connect(tcp_gnss_rx_source_, n, file_sink_.at(n), 0);
                    DLOG(INFO) << "connected source to file sink";
                }
        }
}


void SimpleTcpSignalSource::disconnect(gr::top_block_sptr top_block)
{
    // disconnect null sinks to unused streams
    // for (int n = 0; n < channels_in_tcp_; n++)
    //     {
    //         top_block->disconnect(tcp_gnss_rx_source_, n, null_sinks_.at(n), 0);
    //     }
    if (dump_)
        {
            for (int n = 0; n < channels_in_tcp_; n++)
                {
                    top_block->disconnect(tcp_gnss_rx_source_, n, file_sink_.at(n), 0);
                    DLOG(INFO) << "disconnected source to file sink";
                }
        }
    DLOG(INFO) << "disconnected tcp_source\n";
}


gr::basic_block_sptr SimpleTcpSignalSource::get_left_block()
{
    LOG(WARNING) << "Left block of a signal source should not be retrieved";
    return gr::block_sptr();
}


gr::basic_block_sptr SimpleTcpSignalSource::get_right_block()
{
    return tcp_gnss_rx_source_;
}


gr::basic_block_sptr SimpleTcpSignalSource::get_right_block(__attribute__((unused)) int RF_channel)
{
    return tcp_gnss_rx_source_;
}
