/*!
 * \file gr_complex_ip_packet_source.h
 *
 * \brief Receives ip frames containing samples in UDP frame encapsulation
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


#ifndef GNSS_SDR_GR_COMPLEX_SIMPLE_TCP_SOURCE_H
#define GNSS_SDR_GR_COMPLEX_SIMPLE_TCP_SOURCE_H

#include "gnss_block_interface.h"
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/thread.hpp>
#include <gnuradio/sync_block.h>
#include <arpa/inet.h>
#include <fstream>
#include <ios>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <string>
#include <sys/ioctl.h>

/** \addtogroup Signal_Source
 * \{ */
/** \addtogroup Signal_Source_gnuradio_blocks signal_source_gr_blocks
 * GNU Radio blocks for signal sources.
 * \{ */


class Gr_Complex_Simple_Tcp_Source : virtual public gr::sync_block
{
public:
    using sptr = gnss_shared_ptr<Gr_Complex_Simple_Tcp_Source>;
    static sptr make(const std::string &origin_address,
        int tcp_port,
        const std::string &wire_sample_type,
        size_t item_size,
        bool IQ_swap_);
    Gr_Complex_Simple_Tcp_Source(const std::string &origin_address,
        int tcp_port,
        const std::string &wire_sample_type,
        size_t item_size,
        bool IQ_swap_);
    ~Gr_Complex_Simple_Tcp_Source();

    // Called by gnuradio to enable drivers, etc for i/o devices.
    bool start();

    // Called by gnuradio to disable drivers, etc for i/o devices.
    bool stop();

    // Where all the action really happens
    int work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items);

private:
    void demux_samples(const gr_vector_void_star &output_items, int num_samples_readed, char *buf);
    void my_pcap_loop_thread();
    /*
     * Opens the ethernet device using libpcap raw capture mode
     * If any of these fail, the function returns the error and exits.
     */
    bool open();

    boost::thread *d_pcap_thread;
    boost::mutex d_mutex;

    // boost::lockfree::queue<char, boost::lockfree::fixed_sized<true>> *ring_fifo;

    struct sockaddr_in si_me
    {
    };
    socklen_t d_si_me_len;
    std::string d_src_device;
    std::string d_origin_address;
    // pcap_t *descr;  // ethernet pcap device descriptor
    size_t d_item_size;
    char *fifo_buff;
    // int fifo_read_ptr;
    // int fifo_write_ptr;
    int fifo_items;
    int d_sock_raw;
    int d_sock_accept;
    int d_tcp_port;
    // int d_n_baseband_channels;
    int d_wire_sample_type;
    int d_bytes_per_sample;
    bool d_IQ_swap;
    bool d_fifo_full;
    bool d_thread_status;

    std::ofstream *d_ofile_dump;
};


/** \} */
/** \} */
#endif  //  GNSS_SDR_GR_COMPLEX_SIMPLE_TCP_SOURCE_H
