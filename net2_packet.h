/**
 * @file net_packet.h
 * @brief Network Packet Structure and Handling
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the packet structure and related utilities for the MZ networking
 * library. It provides mechanisms for packet creation, modification, endianness handling,
 * and buffer management for network transmission.
 */

#ifndef NET_PACKET_HEADER_FILE
#define NET_PACKET_HEADER_FILE
#pragma once

#include <string>
#include <format>
#include <type_traits> // For std::is_trivially_copyable_v

#include "net2_config.h"

namespace mz {
    namespace net2 {

        /**
         * @struct packet_header
         * @brief Header structure for network packets containing metadata
         *
         * The packet header contains information about the packet size, command type,
         * timestamp, and two user-definable value fields that can be used for various
         * purposes such as sequence numbers, message IDs, or other metadata.
         */
        struct alignas(8) packet_header {
            uint32_t Length{ 0 };      ///< Length of the packet payload in bytes
            uint32_t Command{ 0 };     ///< Command or message type identifier
            net_time TimeStamp{ 0 };   ///< Timestamp when the packet was created
            uint64_t Value1{ 0 };      ///< User-definable value field 1
            uint64_t Value2{ 0 };      ///< User-definable value field 2

            /**
             * @brief Converts the header to a human-readable string representation
             *
             * @return std::string Formatted string with header field values
             */
            [[nodiscard]] std::string string() const noexcept
            {
                return std::format("{}: #L:{} #C:{} V1:{} V2:{}",
                    TimeStamp.toString(), Length, Command, Value1, Value2);
            }
        };

        // Ensure the packet_header is trivially copyable for performance and safety
        static_assert(std::is_trivially_copyable_v<packet_header>,
            "packet_header must be trivially copyable for safe memory operations");

        /**
         * @class packet
         * @brief Network packet container with header and payload
         *
         * The packet class represents a complete network message, consisting of a header
         * and a variable-length payload. It inherits from mz::endian::Vector to provide
         * binary data storage capabilities with automatic endianness handling.
         */
        class packet : public mz::endian::Vector {
        public:
            /**
             * @name Type Definitions
             * @{
             */
            using value_type = uint8_t;           ///< Type of individual data bytes
            using pointer = value_type*;          ///< Pointer to data byte
            using const_pointer = const value_type*; ///< Const pointer to data byte
            /** @} */

            /**
             * @name Packet Components
             * @{
             */
            packet_header Head;                   ///< Packet metadata header
            uint32_t Action{ 0 };                   ///< Action code for packet processing
            /** @} */

            /**
             * @brief Size of the packet header in bytes
             *
             * This constant is computed at compile time for efficiency.
             */
            static constexpr size_t HeadSize{ sizeof(packet_header) };

            /**
             * @name Constructors
             * @{
             */

             /**
              * @brief Default constructor
              *
              * Creates an empty packet with a zeroed header.
              */
            packet() noexcept = default;

            /**
             * @brief Construct a packet with a specific header
             *
             * @param Header The header to initialize the packet with
             */
            explicit packet(const packet_header& Header) noexcept : Head{ Header } {}

            /**
             * @brief Copy constructor (compiler-generated)
             *
             * @param other The packet to copy from
             */
            packet(const packet& other) = default;

            /**
             * @brief Move constructor (compiler-generated)
             *
             * @param other The packet to move from
             */
            packet(packet&& other) noexcept = default;

            /**
             * @brief Copy assignment operator (compiler-generated)
             *
             * @param other The packet to copy from
             * @return Reference to this packet
             */
            packet& operator=(const packet& other) = default;

            /**
             * @brief Move assignment operator (compiler-generated)
             *
             * @param other The packet to move from
             * @return Reference to this packet
             */
            packet& operator=(packet&& other) noexcept = default;
            /** @} */

            /**
             * @name Data Access Methods
             * @{
             */

             /**
              * @brief Get a span view of the header data excluding the first 4 bytes
              *
              * This allows access to most of the header fields while excluding the Length field,
              * which may need special handling for endianness.
              *
              * @return std::span<uint8_t> View of the header bytes
              */
            [[nodiscard]] auto head_span() noexcept {
                static constexpr size_t SpanSize{ sizeof(packet_header) - 4 };
                return std::span<uint8_t, SpanSize>{
                    reinterpret_cast<uint8_t*>(&Head) + 4, SpanSize};
            }

            /**
             * @brief Get a span view of the packet payload data
             *
             * @return std::span<value_type> View of the packet payload
             */
            [[nodiscard]] auto tail_span() noexcept {
                return std::span<value_type>(data(), size());
            }
            /** @} */

            /**
             * @name Endianness Handling
             * @{
             */

             /**
              * @brief Convert header fields to network byte order
              *
              * This method updates the Length field to reflect the current payload size,
              * then converts all header fields to network byte order if necessary.
              * Call this before sending the packet over the network.
              */
            void SwapNetEndian() noexcept {
                // Update the length field with the current payload size
                Head.Length = static_cast<uint32_t>(size());

                // Only perform byte swapping if the native endianness differs from network endianness
                if constexpr (std::endian::native != net_endian) {
                    Head.Length = mz::endian::swap_bytes(Head.Length);
                    Head.Command = mz::endian::swap_bytes(Head.Command);
                    Head.TimeStamp.m_epochCount = mz::endian::swap_bytes(Head.TimeStamp.m_epochCount);
                    Head.Value1 = mz::endian::swap_bytes(Head.Value1);
                    Head.Value2 = mz::endian::swap_bytes(Head.Value2);
                }
            }

            /**
             * @brief Get the encoded size value from the header
             *
             * Retrieves the Length field from the header, converting from network byte order
             * to host byte order if necessary.
             *
             * @return uint32_t The payload size in host byte order
             */
            [[nodiscard]] uint32_t get_encoded_size() const noexcept {
                uint32_t NetEncodedLength{ Head.Length };
                if constexpr (std::endian::native != net_endian) {
                    NetEncodedLength = mz::endian::swap_bytes(NetEncodedLength);
                }
                return NetEncodedLength;
            }

            /**
             * @brief Update the Length field in the header to match the payload size
             *
             * Sets the Length field based on the current payload size, converting to
             * network byte order if necessary.
             */
            void set_encoded_size() noexcept {
                Head.Length = static_cast<uint32_t>(size());
                if constexpr (std::endian::native != net_endian) {
                    Head.Length = mz::endian::swap_bytes(Head.Length);
                }
            }
            /** @} */

            /**
             * @name ASIO Buffer Interface
             * @{
             */

             /**
              * @brief Get a const buffer view of the header
              *
              * @return asio::const_buffer Buffer view for the header
              */
            [[nodiscard]] asio::const_buffer cbuff_head() const noexcept {
                return asio::const_buffer{ &Head, HeadSize };
            }

            /**
             * @brief Get a const buffer view of the payload
             *
             * @return asio::const_buffer Buffer view for the payload
             */
            [[nodiscard]] asio::const_buffer cbuff_tail() const noexcept {
                return asio::const_buffer{ data(), size() };
            }

            /**
             * @brief Get a mutable buffer view of the header
             *
             * @return asio::mutable_buffer Buffer view for the header
             */
            [[nodiscard]] asio::mutable_buffer mbuff_head() noexcept {
                return asio::mutable_buffer{ &Head, HeadSize };
            }

            /**
             * @brief Get a mutable buffer view of the payload
             *
             * @return asio::mutable_buffer Buffer view for the payload
             */
            [[nodiscard]] asio::mutable_buffer mbuff_tail() noexcept {
                return asio::mutable_buffer{ data(), size() };
            }

            /**
             * @brief Resize the payload and get a mutable buffer view
             *
             * @param TailSize New size for the payload
             * @return asio::mutable_buffer Buffer view for the resized payload
             */
            [[nodiscard]] asio::mutable_buffer mbuff_tail(size_t TailSize) noexcept {
                resize(TailSize);
                return mbuff_tail();
            }

            /**
             * @brief Get an array of const buffers for sending the packet
             *
             * Returns an array containing buffer views for both the header and payload,
             * which can be used with ASIO's scatter-gather operations.
             *
             * @return std::array<asio::const_buffer, 2> Buffer array for sending
             */
            [[nodiscard]] std::array<asio::const_buffer, 2> send_array() const noexcept {
                return { cbuff_head(), cbuff_tail() };
            }

            /**
             * @brief Get an array of mutable buffers for receiving a packet
             *
             * Returns an array containing buffer views for both the header and payload,
             * which can be used with ASIO's scatter-gather operations for receiving.
             *
             * @return std::array<asio::mutable_buffer, 2> Buffer array for receiving
             */
            [[nodiscard]] std::array<asio::mutable_buffer, 2> recv_array() noexcept {
                return { mbuff_head(), mbuff_tail() };
            }
            /** @} */
        };

        // Forward declaration of the connection class
        class connection;

        /**
         * @struct routed_packet
         * @brief A packet with its associated connection
         *
         * This structure bundles a packet with a shared pointer to its source or destination
         * connection, allowing the packet to be routed through a message queue while
         * maintaining information about which connection it belongs to.
         */
        struct routed_packet {
            std::shared_ptr<connection> remote = nullptr; ///< Associated connection
            packet msg;                                  ///< The packet data

            /**
             * @brief Default constructor
             */
            routed_packet() noexcept = default;

            /**
             * @brief Constructor with connection and packet
             *
             * @param conn The connection associated with this packet
             * @param packet The packet data
             */
            routed_packet(std::shared_ptr<connection> conn, packet p) noexcept
                : remote(std::move(conn)), msg(std::move(p)) {
            }
        };

        /*
        // Commented out but kept for reference
        struct connect_handshake {
            uint32_t BcryptCount{ 0 };
            uint32_t UpdateCount{ 0 };
            mz::crypt::BlowSalt Salt{};
            mz::crypt::BlowPass Pass{};

            void generate(mz::Randomizer& rengine);
            packet update_fish(mz::crypt::BlowFish&);
            bool pop_back(mz::endian::Vector& msg) noexcept;

            friend bool operator == (connect_handshake const& L, connect_handshake const& R) noexcept {
                return memcmp(&L, &R, sizeof(connect_handshake)) == 0;
            }

            friend bool operator != (connect_handshake const& L, connect_handshake const& R) noexcept {
                return memcmp(&L, &R, sizeof(connect_handshake)) != 0;
            }
        };
        */

    } // namespace net2
} // namespace mz

#endif // NET_PACKET_HEADER_FILE
