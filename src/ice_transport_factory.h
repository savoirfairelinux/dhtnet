/*
 *  Copyright (C) 2004-2023 Savoir-faire Linux Inc.
 *
 *  Author: Guillaume Roguez <guillaume.roguez@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#pragma once

#include "ice_options.h"
#include "ip_utils.h"

#include <pjnath.h>
#include <pjlib.h>
#include <pjlib-util.h>

#include <functional>
#include <memory>
#include <vector>

namespace dhtnet {

class IceTransportFactory
{
public:
    IceTransportFactory();
    ~IceTransportFactory();

    std::shared_ptr<IceTransport> createTransport(std::string_view name);

    std::unique_ptr<IceTransport> createUTransport(std::string_view name);

    /**
     * PJSIP specifics
     */
    pj_ice_strans_cfg getIceCfg() const { return ice_cfg_; }
    pj_pool_factory* getPoolFactory() { return &cp_->factory; }
    std::shared_ptr<pj_caching_pool> getPoolCaching() { return cp_; }

private:
    std::shared_ptr<pj_caching_pool> cp_;
    pj_ice_strans_cfg ice_cfg_;
};

}; // namespace jami
