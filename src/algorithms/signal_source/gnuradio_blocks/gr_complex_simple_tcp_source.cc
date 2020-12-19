/*!
 * \file gr_complex_simple_udp_source.cc
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


#include "gr_complex_simple_tcp_source.h"
#include <gnuradio/io_signature.h>
#include <array>
#include <cstdint>
#include <utility>
#if HAS_GENERIC_LAMBDA
#else
#include <boost/bind/bind.hpp>
#endif

#include <volk/volk.h>
#include <volk_gnsssdr/volk_gnsssdr.h>

const int FIFO_SIZE = 14720000 * 2;


/* 4 bytes IP address */
typedef struct gr_ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} gr_ip_address;


/* IPv4 header */
typedef struct gr_ip_header
{
    u_char ver_ihl;          // Version (4 bits) + Internet header length (4 bits)
    u_char tos;              // Type of service
    u_short tlen;            // Total length
    u_short identification;  // Identification
    u_short flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl;              // Time to live
    u_char proto;            // Protocol
    u_short crc;             // Header checksum
    gr_ip_address saddr;     // Source address
    gr_ip_address daddr;     // Destination address
    u_int op_pad;            // Option + Padding
} gr_ip_header;

/* UDP header*/
typedef struct gr_udp_header
{
    u_short sport;  // Source port
    u_short dport;  // Destination port
    u_short len;    // Datagram length
    u_short crc;    // Checksum
} gr_udp_header;


Gr_Complex_Simple_Tcp_Source::sptr
Gr_Complex_Simple_Tcp_Source::make(const std::string &origin_address,
    int tcp_port,
    const std::string &wire_sample_type,
    size_t item_size,
    bool IQ_swap_)
{
    return gnuradio::get_initial_sptr(new Gr_Complex_Simple_Tcp_Source(origin_address,
        tcp_port,
        wire_sample_type,
        item_size,
        IQ_swap_));
}

/*
 * The private constructor
 */
Gr_Complex_Simple_Tcp_Source::Gr_Complex_Simple_Tcp_Source(__attribute__((unused)) const std::string &origin_address,
    int tcp_port,
    const std::string &wire_sample_type,
    size_t item_size,
    bool IQ_swap_)
    : gr::sync_block("gr_complex_simple_tcp_source",
          gr::io_signature::make(0, 0, 0),
          gr::io_signature::make(1, 4, item_size))  // 1 to 4 baseband complex channels
{
    // std::cout << "Start Ethernet packet capture\n";

    // d_n_baseband_channels = n_baseband_channels;
    if (wire_sample_type == "cbyte")
        {
            d_wire_sample_type = 1;
            d_bytes_per_sample = 2 * sizeof(int8_t);
            // d_bytes_per_sample = d_n_baseband_channels * 2;
        }
    else if (wire_sample_type == "c4bits")
        {
            d_wire_sample_type = 2;
            d_bytes_per_sample = sizeof(int8_t);
            // d_bytes_per_sample = d_n_baseband_channels;
        }
    else if (wire_sample_type == "cfloat")
        {
            d_wire_sample_type = 3;
            d_bytes_per_sample = 2 * sizeof(float);
            // d_bytes_per_sample = d_n_baseband_channels * 8;
        }
    else if (wire_sample_type == "cshort")
        {
            d_wire_sample_type = 4;
            d_bytes_per_sample = 2 * sizeof(short);
        }
    else
        {
            std::cout << "Unknown wire sample type\n";
            exit(0);
        }
    std::cout << "d_wire_sample_type:" << d_wire_sample_type << '\n';
    // d_src_device = std::move(src_device);
    d_tcp_port = tcp_port;
    // d_udp_payload_size = udp_packet_size;
    d_fifo_full = false;

    // allocate signal samples buffer
    fifo_buff = new char[FIFO_SIZE];
    // fifo_read_ptr = 0;
    // fifo_write_ptr = 0;
    fifo_items = 0;
    d_item_size = item_size;
    d_IQ_swap = IQ_swap_;
    d_sock_raw = 0;
    d_pcap_thread = nullptr;
    d_sock_accept = -1;
    // descr = nullptr;

    memset(reinterpret_cast<char *>(&si_me), 0, sizeof(si_me));
}


// Called by gnuradio to enable drivers, etc for i/o devices.
bool Gr_Complex_Simple_Tcp_Source::start()
{
    std::cout << "gr_complex_simple_tcp_source START\n";
    // open the ethernet device
    if (open() == true)
        {
            // start pcap capture thread
            d_pcap_thread = new boost::thread(
#if HAS_GENERIC_LAMBDA
                [this] { my_pcap_loop_thread(); });
#else
                boost::bind(&Gr_Complex_Simple_Tcp_Source::my_pcap_loop_thread, this, descr));
#endif
            return true;
        }
    return false;
}


// Called by gnuradio to disable drivers, etc for i/o devices.
bool Gr_Complex_Simple_Tcp_Source::stop()
{
    std::cout << "gr_complex_simple_tcp_source STOP\n";
    // if (descr != nullptr)
    if (1)
        {
            // pcap_breakloop(descr);
            d_pcap_thread->join();
            // pcap_close(descr);
        }
    return true;
}


bool Gr_Complex_Simple_Tcp_Source::open()
{
    boost::mutex::scoped_lock lock(d_mutex);  // hold mutex for duration of this function
    d_sock_raw = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (d_sock_raw == -1)
        {
            std::cout << "Error opening TCP socket\n";
            return false;
        }

    // zero out the structure
    memset(reinterpret_cast<char *>(&si_me), 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(d_tcp_port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    d_si_me_len = sizeof(si_me);

    // set reuseaddr 
    int sock_opt = 1;
    if (setsockopt(d_sock_raw, SOL_SOCKET, SO_REUSEADDR, &sock_opt, sizeof(sock_opt)) == -1)
    {
        std::cout << "Error setting port reuse\n";
    }

    // bind socket to port
    if (bind(d_sock_raw, reinterpret_cast<struct sockaddr *>(&si_me), d_si_me_len) == -1)
        {
            std::cout << "Error binding TCP socket\n";
            return false;
        }
    // debug file
    d_ofile_dump = new std::ofstream("/tmp/signalsource.dat");
    return true;
}


Gr_Complex_Simple_Tcp_Source::~Gr_Complex_Simple_Tcp_Source()
{
    if (d_pcap_thread != nullptr)
        {
            delete d_pcap_thread;
        }
    delete fifo_buff;
    std::cout << "Stop Ethernet packet capture\n";
    d_ofile_dump->flush();
    d_ofile_dump->close();
}

void Gr_Complex_Simple_Tcp_Source::my_pcap_loop_thread()
{
    if (listen(d_sock_raw, 0) == -1)
        {
            std::cout << "Error listening TCP socket: " << strerror(errno);
        }
    do
        {
            int rc = accept(d_sock_raw, (struct sockaddr *)&si_me, &d_si_me_len);
            if (rc == -1)
                {
                    sleep(1);
                }
            else
                {
                    std::cout << "Accept a connect\n";
                    d_sock_accept = rc;
                }
        }
    while (1);
}

// Read data from fifo, de-interleave baseband data, put them into output_items
void Gr_Complex_Simple_Tcp_Source::demux_samples(const gr_vector_void_star &output_items, int num_samples_read, char *buf)
{
    for (int n = 0; n < num_samples_read; n++)
        {
            switch (d_wire_sample_type)
                {
                case 1:  // interleaved byte samples
                    // FIXME modify this
                    for (auto &output_item : output_items)
                        {
                            int8_t real;
                            int8_t imag;
                            // real = fifo_buff[fifo_read_ptr++];
                            // imag = fifo_buff[fifo_read_ptr++];
                            real = *(buf + n);
                            imag = *(buf + n + 1);
                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                }
                        }
                    break;
                case 2:  // 4-bit samples
                    // FIXME modify this
                    // volk_gnsssdr_16ic_convert_32fc(out, in, 8192);
                    for (auto &output_item : output_items)
                        {
                            int8_t real;
                            int8_t imag;
                            uint8_t tmp_char2 = 0;
                            // tmp_char2 = fifo_buff[fifo_read_ptr] & 0x0F;
                            if (tmp_char2 >= 8)
                                {
                                    real = 2 * (tmp_char2 - 16) + 1;
                                }
                            else
                                {
                                    real = 2 * tmp_char2 + 1;
                                }
                            // tmp_char2 = fifo_buff[fifo_read_ptr++] >> 4;
                            tmp_char2 = tmp_char2 & 0x0F;
                            if (tmp_char2 >= 8)
                                {
                                    imag = 2 * (tmp_char2 - 16) + 1;
                                }
                            else
                                {
                                    imag = 2 * tmp_char2 + 1;
                                }
                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                }
                        }

                    break;
                case 3:  // interleaved float samples
                    for (auto &output_item : output_items)
                        {
                            float real;
                            float imag;
                            memcpy(&real, &buf[n * d_bytes_per_sample], sizeof(float));
                            memcpy(&imag, &buf[n * d_bytes_per_sample + sizeof(float)], sizeof(float));
                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(real, imag);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(imag, real);
                                }

                            // static_cast<std::vector<gr_complex *>>(output_items) =
                        }
                    break;
                case 4:  // interleaved short samples
                    // FIXME gr_complex cannot accept short type, convert required
                    for (void *const &output_item : output_items)
                        {
                            short real;
                            short imag;
                            memcpy(&real, &buf[2 * n * sizeof(short)], sizeof(short));
                            memcpy(&imag, &buf[2 * n * sizeof(short) + sizeof(short)], sizeof(short));
                            if (d_IQ_swap)
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(real / 100.0f, imag / 100.0f);
                                }
                            else
                                {
                                    static_cast<gr_complex *>(output_item)[n] = gr_complex(imag / 100.0f, real / 100.0f);
                                }
                        }
                    break;
                default:
                    std::cout << "Unknown wire sample type\n";
                    exit(0);
                }
        }
}


int Gr_Complex_Simple_Tcp_Source::work(int noutput_items,
    __attribute__((unused)) gr_vector_const_void_star &input_items,
    gr_vector_void_star &output_items)
{
    // send samples to next GNU Radio block
    // boost::mutex::scoped_lock lock(d_mutex);  // hold mutex for duration of this function

    if (d_sock_raw == 0 || d_sock_raw == -1)
        {
            return 0;
        }

    // get bytes from tcp buffer
    uint8_t recv_buf[131072] = {0};
    int num_bytes_read = recv(d_sock_accept, recv_buf, noutput_items * d_bytes_per_sample, MSG_WAITALL);
    if (num_bytes_read == 0 || num_bytes_read == -1)
        {
            return 0;
        }
    int num_samples_read = num_bytes_read / d_bytes_per_sample;

    if (num_samples_read != noutput_items)
        {
            std::cout << "number of required sample and number of read out samples disagree\n";
        }

    // read all in a single loop
    demux_samples(output_items, num_samples_read, reinterpret_cast<char *>(recv_buf));

    for (uint64_t n = 0; n < output_items.size(); n++)
        {
            // notify the scheduler
            produce(static_cast<int>(n), num_samples_read);
        }
    return this->WORK_CALLED_PRODUCE;
}
