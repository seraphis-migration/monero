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

// Core hash functions for Seraphis (note: this implementation satisfies the Jamtis specification).


#pragma once

//local headers

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <memory>

//forward declarations


namespace sp
{

class DataSource final
{
//member types
    /// concept: data source
    class DataSourceConcept
    {
    public:
        virtual ~DataSourceConcept() = default;
        DataSourceConcept& operator=(DataSourceConcept&&) = delete;
        virtual const void* data() const = 0;
        virtual std::size_t size() const = 0;
    };

    /// model: data source
    template<typename SourceT>
    class DataSourceModel final : public DataSourceConcept
    {
    public:
        /// normal constructor: wrap a data source satisfying the .data(), .size() concept
        DataSourceModel(const SourceT &source) : m_source{source} {}
        /// disable copy/move (this is a scoped manager [reference wrapper])
        DataSourceModel& operator=(DataSourceModel&&) = delete;
        /// data source's data
        const void* data() const override { return m_source.data(); }
        /// data source's data size
        std::size_t size() const override { return m_source.size(); }

    private:
        /// underlying data source
        const SourceT &m_source;
    };

public:
//constructors
    /// normal constructor: wrap a data source object
    template<typename SourceT>
    DataSource(const SourceT &source)
    {
        m_source_concept = std::make_unique<DataSourceModel<SourceT>>(source);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    DataSource& operator=(DataSource&&) = delete;

//member functions
    /// data source's data
    const void* data() const { return m_source_concept->data(); }
    /// data source's data size
    std::size_t size() const { return m_source_concept->size(); }

//member variables
private:
    /// underlying data source
    std::unique_ptr<DataSourceConcept> m_source_concept;
};

/// H_1(x): 1-byte output
void sp_hash_to_1(const DataSource &data_source, unsigned char *hash_out);
/// H_8(x): 8-byte output
void sp_hash_to_8(const DataSource &data_source, unsigned char *hash_out);
/// H_16(x): 16-byte output
void sp_hash_to_16(const DataSource &data_source, unsigned char *hash_out);
/// H_32(x): 32-byte output
void sp_hash_to_32(const DataSource &data_source, unsigned char *hash_out);
/// H_64(x): 64-byte output
void sp_hash_to_64(const DataSource &data_source, unsigned char *hash_out);
/// H_n(x): Ed25519 group scalar output (32 bytes)
void sp_hash_to_scalar(const DataSource &data_source, unsigned char *hash_out);
/// H_n[k](x): Ed25519 group scalar output (32 bytes); 32-byte key
void sp_derive_key(const unsigned char *derivation_key, const DataSource &data_source, unsigned char *hash_out);
/// H_32[k](x): 32-byte output; 32-byte key
void sp_derive_secret(const unsigned char *derivation_key, const DataSource &data_source, unsigned char *hash_out);

} //namespace sp
