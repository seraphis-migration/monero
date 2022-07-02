// Copyright (c) 2021, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// NOT FOR PRODUCTION

//paired header
#include "sp_multiexp.h"

//local headers
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "misc_log_ex.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"
#include "sp_generator_factory.h"

//third party headers

//standard headers
#include <iostream>
#include <list>
#include <vector>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void weight_scalar(const boost::optional<rct::key> &weight, rct::key &scalar_inout)
{
    // s *= weight
    if (weight)
        sc_mul(scalar_inout.bytes, weight->bytes, scalar_inout.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void update_scalar(const boost::optional<rct::key> &new_scalar, rct::key &scalar_inout)
{
    // s += s_new
    if (new_scalar)
        sc_add(scalar_inout.bytes, scalar_inout.bytes, new_scalar->bytes);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
SpMultiexpBuilder::SpMultiexpBuilder(const rct::key &weight,
    const std::size_t estimated_num_predefined_generator_elements,
    const std::size_t estimated_num_user_defined_elements)
{
    CHECK_AND_ASSERT_THROW_MES(!(weight == rct::zero()), "multiexp builder: element weight is zero.");
    CHECK_AND_ASSERT_THROW_MES(sc_check(weight.bytes) == 0, "multiexp builder: element weight is not canonical.");

    // only initialize weight if not identity
    if (!(weight == rct::identity()))
        m_weight = weight;

    m_predef_scalars.resize(estimated_num_predefined_generator_elements, rct::zero());
    m_user_def_elements.reserve(estimated_num_user_defined_elements);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_G_element(rct::key scalar)
{
    weight_scalar(m_weight, scalar);

    if (!m_G_scalar)
        m_G_scalar = scalar;
    else
        sc_add(m_G_scalar->bytes, m_G_scalar->bytes, scalar.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_H_element(rct::key scalar)
{
    weight_scalar(m_weight, scalar);

    if (!m_H_scalar)
        m_H_scalar = scalar;
    else
        sc_add(m_H_scalar->bytes, m_H_scalar->bytes, scalar.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_U_element(rct::key scalar)
{
    weight_scalar(m_weight, scalar);

    if (!m_U_scalar)
        m_U_scalar = scalar;
    else
        sc_add(m_U_scalar->bytes, m_U_scalar->bytes, scalar.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_X_element(rct::key scalar)
{
    weight_scalar(m_weight, scalar);

    if (!m_X_scalar)
        m_X_scalar = scalar;
    else
        sc_add(m_X_scalar->bytes, m_X_scalar->bytes, scalar.bytes);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_element_at_generator_index(rct::key scalar, const std::size_t predef_generator_index)
{
    weight_scalar(m_weight, scalar);

    if (m_predef_scalars.size() <= predef_generator_index)
        m_predef_scalars.resize(predef_generator_index + 1, rct::zero());

    if (m_predef_scalars[predef_generator_index] == rct::zero())
        m_predef_scalars[predef_generator_index] = scalar;
    else
    {
        sc_add(m_predef_scalars[predef_generator_index].bytes,
            m_predef_scalars[predef_generator_index].bytes,
            scalar.bytes);
    }
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_element(rct::key scalar, const ge_p3 &base_point)
{
    // early return on cheap zero scalar check
    if (scalar == rct::zero())
        return;

    weight_scalar(m_weight, scalar);

    m_user_def_elements.emplace_back(scalar, base_point);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_element(const rct::key &scalar, const rct::key &base_point)
{
    // early return on cheap identity check
    if (base_point == rct::identity())
        return;

    ge_p3 base_point_p3;
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&base_point_p3, base_point.bytes) == 0,
        "ge_frombytes_vartime failed!");
    this->add_element(scalar, base_point_p3);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexpBuilder::add_element(const rct::key &scalar, const crypto::public_key &base_point)
{
    this->add_element(scalar, rct::pk2rct(base_point));
}
//-------------------------------------------------------------------------------------------------------------------
SpMultiexp::SpMultiexp(const std::list<SpMultiexpBuilder> &multiexp_builders)
{
    // figure out how many elements there are
    std::size_t num_predef_gen_elements{0};
    std::size_t num_user_def_elements{0};

    for (const SpMultiexpBuilder &multiexp_builder : multiexp_builders)
    {
        if (num_predef_gen_elements < multiexp_builder.m_predef_scalars.size())
            num_predef_gen_elements = multiexp_builder.m_predef_scalars.size();

        num_user_def_elements += multiexp_builder.m_user_def_elements.size();
    }

    // 1. prepare generators
    std::shared_ptr<rct::pippenger_cached_data> cached_base_points = std::make_shared<rct::pippenger_cached_data>();
    cached_base_points->reserve(4 + num_predef_gen_elements + num_user_def_elements);
    ge_cached ge_cached_identity;
    ge_p3_to_cached(&ge_cached_identity, &ge_p3_identity);
    cached_base_points->resize(4 + num_predef_gen_elements, ge_cached_identity);

    std::vector<rct::MultiexpData> elements_collected;
    elements_collected.reserve(4 + num_predef_gen_elements + num_user_def_elements);
    elements_collected.resize(4 + num_predef_gen_elements, {rct::zero(), ge_p3_identity});

    (*cached_base_points)[0] = crypto::get_G_cached();
    (*cached_base_points)[1] = crypto::get_H_cached();
    (*cached_base_points)[2] = crypto::get_U_cached();
    (*cached_base_points)[3] = crypto::get_X_cached();

    elements_collected[0].point = crypto::get_G_p3();
    elements_collected[1].point = crypto::get_H_p3();
    elements_collected[2].point = crypto::get_U_p3();
    elements_collected[3].point = crypto::get_X_p3();

    for (std::size_t predef_generator_index{0}; predef_generator_index < num_predef_gen_elements; ++predef_generator_index)
    {
        (*cached_base_points)[4 + predef_generator_index] =
            generator_factory::get_generator_at_index_cached(predef_generator_index);

        elements_collected[4 + predef_generator_index].point =
            generator_factory::get_generator_at_index_p3(predef_generator_index);
    }

    // 2. collect scalars and expand cached points with user-defined elements
    for (const SpMultiexpBuilder &multiexp_builder : multiexp_builders)
    {
        // main generators
        update_scalar(multiexp_builder.m_G_scalar, elements_collected[0].scalar);
        update_scalar(multiexp_builder.m_H_scalar, elements_collected[1].scalar);
        update_scalar(multiexp_builder.m_U_scalar, elements_collected[2].scalar);
        update_scalar(multiexp_builder.m_X_scalar, elements_collected[3].scalar);

        // pre-defined generators
        for (std::size_t predef_generator_index{0};
            predef_generator_index < multiexp_builder.m_predef_scalars.size();
            ++predef_generator_index)
        {
            sc_add(elements_collected[4 + predef_generator_index].scalar.bytes,
                elements_collected[4 + predef_generator_index].scalar.bytes,
                multiexp_builder.m_predef_scalars[predef_generator_index].bytes);
        }

        // user-defined elements
        for (const rct::MultiexpData &element : multiexp_builder.m_user_def_elements)
        {
            cached_base_points->emplace_back();
            ge_p3_to_cached(&(cached_base_points->back()), &element.point);
            elements_collected.emplace_back(element.scalar, element.point);
        }
    }

    // 3. evaluate the multiexponentiation
    m_result = pippenger_p3(elements_collected, cached_base_points, cached_base_points->size());
}
//-------------------------------------------------------------------------------------------------------------------
bool SpMultiexp::evaluates_to_point_at_infinity() const
{
    return ge_p3_is_point_at_infinity_vartime(&m_result) != 0;
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexp::get_result(rct::key &result_out) const
{
    ge_p3_tobytes(result_out.bytes, &m_result);
}
//-------------------------------------------------------------------------------------------------------------------
void SpMultiexp::get_result_p3(ge_p3 &result_out) const
{
    result_out = m_result;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace sp
