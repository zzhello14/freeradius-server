/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * @file src/lib/aka-sim/sim_attrs.h
 * @brief Attributes to EAP-SIM/AKA/AKA' clients and servers.
 *
 * @copyright 2003-2016 The FreeRADIUS server project
 */
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>
#include <freeradius-devel/protocol/eap/aka-sim/rfc4187.h>
#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>
#include <freeradius-devel/protocol/eap/aka-sim/rfc4187.h>
#include <freeradius-devel/protocol/eap/aka-sim/freeradius.h>

extern fr_dict_t *dict_freeradius;
extern fr_dict_t *dict_radius;
extern fr_dict_t *dict_eap_aka_sim;

extern fr_dict_attr_t const *attr_eap_aka_sim_ak;
extern fr_dict_attr_t const *attr_eap_aka_sim_autn;
extern fr_dict_attr_t const *attr_eap_aka_sim_auts;
extern fr_dict_attr_t const *attr_eap_aka_sim_checkcode;
extern fr_dict_attr_t const *attr_eap_aka_sim_ck;
extern fr_dict_attr_t const *attr_eap_aka_sim_counter;
extern fr_dict_attr_t const *attr_eap_aka_sim_identity_type;
extern fr_dict_attr_t const *attr_eap_aka_sim_identity;
extern fr_dict_attr_t const *attr_eap_aka_sim_ik;
extern fr_dict_attr_t const *attr_eap_aka_sim_iv;
extern fr_dict_attr_t const *attr_eap_aka_sim_iv;
extern fr_dict_attr_t const *attr_eap_aka_sim_k_re;
extern fr_dict_attr_t const *attr_eap_aka_sim_kc;
extern fr_dict_attr_t const *attr_eap_aka_sim_mac;
extern fr_dict_attr_t const *attr_eap_aka_sim_method_hint;
extern fr_dict_attr_t const *attr_eap_aka_sim_mk;
extern fr_dict_attr_t const *attr_eap_aka_sim_padding;
extern fr_dict_attr_t const *attr_eap_aka_sim_rand;
extern fr_dict_attr_t const *attr_eap_aka_sim_res;
extern fr_dict_attr_t const *attr_eap_aka_sim_sres;
extern fr_dict_attr_t const *attr_eap_aka_sim_subtype;
extern fr_dict_attr_t const *attr_eap_aka_sim_xres;

extern fr_dict_attr_t const *attr_session_data;
extern fr_dict_attr_t const *attr_sim_algo_version;
extern fr_dict_attr_t const *attr_sim_amf;
extern fr_dict_attr_t const *attr_sim_ki;
extern fr_dict_attr_t const *attr_sim_op;
extern fr_dict_attr_t const *attr_sim_opc;
extern fr_dict_attr_t const *attr_sim_sqn;
