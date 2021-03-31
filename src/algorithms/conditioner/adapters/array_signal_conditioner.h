/*!
 * \file array_signal_conditioner.h
 * \brief It wraps blocks to change data type, filter and resample input data, adapted to array receiver
 * \author Javier Arribas jarribas (at) cttc.es
 *
 *
 * -----------------------------------------------------------------------------
 *
 * GNSS-SDR is a Global Navigation Satellite System software-defined receiver.
 * This file is part of GNSS-SDR.
 *
 * Copyright (C) 2010-2020  (see AUTHORS file for a list of contributors)
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * -----------------------------------------------------------------------------
 */

#ifndef GNSS_SDR_ARRAY_SIGNAL_CONDITIONER_H
#define GNSS_SDR_ARRAY_SIGNAL_CONDITIONER_H


#include "gnss_block_interface.h"
#include <gnuradio/block.h>
#include <cstddef>
#include <memory>
#include <string>

/** \addtogroup Signal_Conditioner
 * \{ */
/** \addtogroup Signal_Conditioner_adapters
 * \{ */


class ConfigurationInterface;


/*!
 * \brief This class wraps blocks to change data_type_adapter, input_filter and resampler
 * to be applied to the input flow of sampled signal.
 */
class ArraySignalConditioner : public GNSSBlockInterface
{
public:
    //! Constructor
    ArraySignalConditioner(std::shared_ptr<GNSSBlockInterface> data_type_adapt,
        std::shared_ptr<GNSSBlockInterface> in_filt,
        std::shared_ptr<GNSSBlockInterface> res,
        std::string role);

    //! Destructor
    ~ArraySignalConditioner() = default;

    void connect(gr::top_block_sptr top_block) override;
    void disconnect(gr::top_block_sptr top_block) override;
    gr::basic_block_sptr get_left_block() override;
    gr::basic_block_sptr get_right_block() override;

    inline std::string role() override { return role_; }
    //! Returns "Array_Signal_Conditioner"
    inline std::string implementation() override { return "Array_Signal_Conditioner"; }
    inline size_t item_size() override { return data_type_adapt_->item_size(); }

    inline std::shared_ptr<GNSSBlockInterface> data_type_adapter() { return data_type_adapt_; }
    inline std::shared_ptr<GNSSBlockInterface> input_filter() { return in_filt_; }
    inline std::shared_ptr<GNSSBlockInterface> resampler() { return res_; }

private:
    std::shared_ptr<GNSSBlockInterface> data_type_adapt_;
    std::shared_ptr<GNSSBlockInterface> in_filt_;
    std::shared_ptr<GNSSBlockInterface> res_;
    std::string role_;
    bool connected_;
};


/** \} */
/** \} */
#endif  // GNSS_SDR_SIGNAL_CONDITIONER_H
