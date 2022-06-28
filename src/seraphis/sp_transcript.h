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

// Transcript class for assembling data that needs to be hashed.


#pragma once

//local headers
#include "crypto/crypto.h"
#include "ringct/rctTypes.h"
#include "seraphis_config_temp.h"
#include "wipeable_string.h"

//third party headers
#include <boost/utility/string_ref.hpp>

//standard headers
#include <list>
#include <string>
#include <type_traits>
#include <vector>

//forward declarations


namespace sp
{

////
// SpTranscriptBuilder
// - build a transcript
// - data types: objects are prefixed with a label
//     - unsigned int: uint_flag || varint(uint_variable)
//     - signed int: int_flag || uchar{int_variable < 0 ? 1 : 0} || varint(abs(int_variable))
//     - byte buffer (assumed little-endian): buffer_flag || buffer_length || buffer
//       - all labels are treated as byte buffers
//     - named container: container_flag || container_name || data_member1 || ... || container_terminator_flag
//     - list-type container (same-type elements only): list_flag || list_length || element1 || element2 || ...
// - the transcript can be used by passing a predicate to use_transcript()
// - simple mode: exclude all labels, flags, and lengths
///
class SpTranscriptBuilder final
{
//member types
    /// flags for separating items added to the transcript
    enum SpTranscriptBuilderFlag : unsigned char
    {
        EXTERNAL_PREDICATE_CALL = 0,
        UNSIGNED_INTEGER = 1,
        SIGNED_INTEGER = 2,
        BYTE_BUFFER = 3,
        NAMED_CONTAINER = 4,
        NAMED_CONTAINER_TERMINATOR = 5,
        LIST_TYPE_CONTAINER = 6,
        TRANSCRIPT_CLONE = 7
    };

//core member functions
    void append_uint(const std::uint64_t unsigned_integer)
    {
        unsigned char v_variable[(sizeof(std::uint64_t) * 8 + 6) / 7];
        unsigned char *v_variable_end = v_variable;

        // append uint to string as a varint
        v_variable_end = v_variable;
        tools::write_varint(v_variable_end, unsigned_integer);
        assert(v_variable_end <= v_variable + sizeof(v_variable));
        m_transcript.append(reinterpret_cast<const char*>(v_variable), v_variable_end - v_variable);
    }
    void append_flag(const SpTranscriptBuilderFlag flag)
    {
        if (m_simple_mode)
            return;

        static_assert(sizeof(SpTranscriptBuilderFlag) <= sizeof(std::uint64_t),
            "SpTranscriptBuilder: flag type greater than uint64_t.");
        append_uint(static_cast<std::uint64_t>(flag));
    }
    void append_length(const std::size_t length)
    {
        if (m_simple_mode)
            return;

        static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t), "SpTranscriptBuilder: size_t greater than uint64_t.");
        append_uint(static_cast<std::uint64_t>(length));
    }
    void append_buffer(const void *data, const std::size_t length)
    {
        append_flag(SpTranscriptBuilderFlag::BYTE_BUFFER);
        append_length(length);
        m_transcript.append(reinterpret_cast<const char*>(data), length);
    }
    void append_label(const boost::string_ref label)
    {
        if (m_simple_mode)
            return;

        append_buffer(label.data(), label.size());
    }
    void begin_named_container(const boost::string_ref container_name)
    {
        append_flag(SpTranscriptBuilderFlag::NAMED_CONTAINER);
        append_label(container_name);
    }
    void end_named_container()
    {
        append_flag(SpTranscriptBuilderFlag::NAMED_CONTAINER_TERMINATOR);
    }
    void begin_list_type_container(const std::size_t &list_length)
    {
        append_flag(SpTranscriptBuilderFlag::LIST_TYPE_CONTAINER);
        append_length(list_length);
    }

public:
//constructors
    /// normal constructor: start building a transcript with the domain separator
    SpTranscriptBuilder(const std::size_t estimated_data_size, const bool mode) :
        m_simple_mode{mode}
    {
        m_transcript.reserve(2 * estimated_data_size + 20);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [of the 'transcript' concept])
    SpTranscriptBuilder& operator=(SpTranscriptBuilder&&) = delete;

//member functions
    /// transcript builders
    void append(const boost::string_ref label, const rct::key &key_buffer)
    {
        append_label(label);
        append_buffer(key_buffer.bytes, sizeof(key_buffer));
    }
    void append(const boost::string_ref label, const crypto::secret_key &point_buffer)
    {
        append_label(label);
        append_buffer(point_buffer.data, sizeof(point_buffer));
    }
    void append(const boost::string_ref label, const crypto::public_key &scalar_buffer)
    {
        append_label(label);
        append_buffer(scalar_buffer.data, sizeof(scalar_buffer));
    }
    void append(const boost::string_ref label, const crypto::key_derivation &derivation_buffer)
    {
        append_label(label);
        append_buffer(derivation_buffer.data, sizeof(derivation_buffer));
    }
    void append(const boost::string_ref label, const crypto::key_image &key_image_buffer)
    {
        append_label(label);
        append_buffer(key_image_buffer.data, sizeof(key_image_buffer));
    }
    void append(const boost::string_ref label, const std::string &string_buffer)
    {
        append_label(label);
        append_buffer(string_buffer.data(), string_buffer.size());
    }
    void append(const boost::string_ref label, const epee::wipeable_string &string_buffer)
    {
        append_label(label);
        append_buffer(string_buffer.data(), string_buffer.size());
    }
    void append(const boost::string_ref label, const boost::string_ref string_buffer)
    {
        append_label(label);
        append_buffer(string_buffer.data(), string_buffer.size());
    }
    template<std::size_t Sz>
    void append(const boost::string_ref label, const unsigned char(&uchar_buffer)[Sz])
    {
        append_label(label);
        append_buffer(uchar_buffer, Sz);
    }
    template<std::size_t Sz>
    void append(const boost::string_ref label, const char(&char_buffer)[Sz])
    {
        append_label(label);
        append_buffer(char_buffer, Sz);
    }
    void append(const boost::string_ref label, const std::vector<unsigned char> &vector_buffer)
    {
        append_label(label);
        append_buffer(vector_buffer.data(), vector_buffer.size());
    }
    void append(const boost::string_ref label, const std::vector<char> &vector_buffer)
    {
        append_label(label);
        append_buffer(vector_buffer.data(), vector_buffer.size());
    }
    template<typename T,
        std::enable_if_t<std::is_unsigned<T>::value, bool> = true>
    void append(const boost::string_ref label, const T unsigned_integer)
    {
        static_assert(sizeof(T) <= sizeof(std::uint64_t), "SpTranscriptBuilderFlag: unsupported unsigned integer type.");
        append_label(label);
        append_flag(SpTranscriptBuilderFlag::UNSIGNED_INTEGER);
        append_uint(unsigned_integer);
    }
    template<typename T,
        std::enable_if_t<std::is_integral<T>::value, bool> = true,
        std::enable_if_t<!std::is_unsigned<T>::value, bool> = true>
    void append(const boost::string_ref label, const T signed_integer)
    {
        static_assert(sizeof(T) <= sizeof(std::uint64_t), "SpTranscriptBuilderFlag: unsupported signed integer type.");
        append_label(label);
        append_flag(SpTranscriptBuilderFlag::SIGNED_INTEGER);
        if (signed_integer > 0)
        {
            // positive integer: byte{0} || varint(uint(int_variable))
            append_uint(0);
            append_uint(static_cast<std::uint64_t>(signed_integer));
        }
        else
        {
            // negative integer: byte{1} || varint(uint(abs(int_variable)))
            append_uint(1);
            append_uint(static_cast<std::uint64_t>(-signed_integer));
        }
    }
    template<typename T,
        std::enable_if_t<!std::is_integral<T>::value, bool> = true>
    void append(const boost::string_ref label, const T &named_container)
    {
        // named containers must satisfy two concepts:
        //   const boost::string_ref get_container_name(const T &container);
        //   void append_to_transcript(const T &container, SpTranscriptBuilder &transcript_inout);
        append_label(label);
        begin_named_container(get_container_name(named_container));
        append_to_transcript(named_container, *this);
        end_named_container();
    }
    template<typename T>
    void append(const boost::string_ref label, const std::vector<T> &list_container)
    {
        append_label(label);
        begin_list_type_container(list_container.size());
        for (const T &element : list_container)
            append("", element);
    }
    template<typename T>
    void append(const boost::string_ref label, const std::list<T> &list_container)
    {
        append_label(label);
        begin_list_type_container(list_container.size());
        for (const T &element : list_container)
            append("", element);
    }

    /// access the transcript data
    const void* data() const { return m_transcript.data(); }
    std::size_t size() const { return m_transcript.size(); }

//member variables
private:
    /// if set, exclude: labels, flags, lengths
    bool m_simple_mode;
    /// the transcript itself (wipeable in case it contains sensitive data)
    epee::wipeable_string m_transcript;
};

////
// SpFSTranscript
// - build a Fiat-Shamir transcript
// - main format: transcript_prefix || domain_separator || object1_label || object1 || object2_label || object2 || ...
///
class SpFSTranscript final
{
public:
//constructors
    /// normal constructor: start building a transcript with the domain separator
    SpFSTranscript(const boost::string_ref domain_separator, const std::size_t estimated_data_size) :
        m_transcript_builder{15 + domain_separator.size() + estimated_data_size, true}
    {
        // transcript = sp_FS_transcript || domain_separator
        m_transcript_builder.append("FS_transcript", config::SERAPHIS_FS_TRANSCRIPT_PREFIX);
        m_transcript_builder.append("domain_separator", domain_separator);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [of the 'transcript' concept])
    SpFSTranscript& operator=(SpFSTranscript&&) = delete;

//member functions
    /// transcript builders
    template<typename T>
    void append(const boost::string_ref label, const T &value)
    {
        m_transcript_builder.append(label, value);
    }

    /// access the transcript data
    const void* data() const { return m_transcript_builder.data(); }
    std::size_t size() const { return m_transcript_builder.size(); }

//member variables
private:
    /// underlying transcript builder
    SpTranscriptBuilder m_transcript_builder;
};

////
// SpFSTranscript
// - build a data string for a key-derivation function
// - main format: domain_separator || object1 || object2 || ...
// - simple transcript mode: no labels, flags, or lengths
///
class SpKDFTranscript final
{
public:
//constructors
    /// normal constructor: start building a transcript with the domain separator
    SpKDFTranscript(const boost::string_ref domain_separator, const std::size_t estimated_data_size) :
        m_transcript_builder{domain_separator.size() + estimated_data_size, false}
    {
        // transcript = domain_separator
        m_transcript_builder.append("", domain_separator);
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [of the 'transcript' concept])
    SpKDFTranscript& operator=(SpKDFTranscript&&) = delete;

//member functions
    /// transcript builders
    template<typename T>
    void append(const boost::string_ref, const T &value)
    {
        m_transcript_builder.append("", value);
    }

    /// access the transcript data
    const void* data() const { return m_transcript_builder.data(); }
    std::size_t size() const { return m_transcript_builder.size(); }

//member variables
private:
    /// underlying transcript builder
    SpTranscriptBuilder m_transcript_builder;
};

} //namespace sp
