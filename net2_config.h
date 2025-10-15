/**
 * @file net2_config.h
 * @brief Network Configuration Header for the MZ Networking Library
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header provides the core configuration and type definitions for
 * the MZ networking library (version 2). It is designed to work across
 * multiple platforms while providing a consistent interface for network
 * operations using the ASIO library.
 */

#ifndef MZ_NET_CONFIG_HEADER_FILE
#define MZ_NET_CONFIG_HEADER_FILE
#pragma once

 //----------------------------------------------------------------------------
 // Platform Detection and Configuration
 //----------------------------------------------------------------------------

 // Windows-specific configurations
#ifdef _WIN32
    // Define Windows version targets for compatibility
    // 0x0A00 corresponds to Windows 10
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#ifndef WINVER
#define WINVER 0x0A00
#endif

// Suppress deprecated Windows socket API warnings
#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

// Exclude rarely-used Windows headers for faster compilation
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

// POSIX/Unix-specific configurations
#if defined(__unix__) || defined(__APPLE__)
    // Add any Unix-specific configurations here if needed
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#endif

//----------------------------------------------------------------------------
// Standard Library Includes
//----------------------------------------------------------------------------

// Core data type and container support
#include <cstdint>        // Fixed-width integer types
#include <memory>         // Smart pointers
#include <deque>          // Double-ended queue
#include <optional>       // Optional values
#include <vector>         // Dynamic arrays
#include <algorithm>      // Algorithms like std::find, std::sort
#include <array>          // Fixed-size arrays
#include <string>         // String handling

// Modern C++ feature support (C++17/C++20)
#include <concepts>       // Concept definitions
#include <span>           // Non-owning view of a contiguous sequence
#include <bit>            // Bit manipulation utilities

// Time handling
#include <chrono>         // Time utilities
#include <format>         // Text formatting

//----------------------------------------------------------------------------
// Project-specific Includes
//----------------------------------------------------------------------------

#include "Logger.h"
#include "EndianVector.h"
#include "EndianByteArray.h"
#include "blow_crypt.h"
#include "TimeConversions.h"

//----------------------------------------------------------------------------
// ASIO Library Configuration
//----------------------------------------------------------------------------

// Use standalone ASIO (not as part of Boost)
#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif

// Include the ASIO library headers
#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>

/**
 * @namespace mz
 * @brief Root namespace for all MZ library components
 */
namespace mz {

    /**
     * @namespace mz::net
     * @brief Namespace for the version 2 of the MZ networking library
     */
    namespace net2 {

        //------------------------------------------------------------------------
        // Network Endianness Configuration
        //------------------------------------------------------------------------

        /**
         * @brief Defines the network endianness used for data transmission
         *
         * Network byte order is standardized as big-endian, but this library uses
         * little-endian for compatibility with specific protocols.
         */
        static constexpr auto net_endian{ std::endian::little };

        //------------------------------------------------------------------------
        // Time-Related Type Definitions
        //------------------------------------------------------------------------

        /**
         * @brief Duration type used for network timing operations
         *
         * Uses microsecond precision for fine-grained timing control in networking
         * operations.
         */
        using net_duration = std::chrono::duration<std::chrono::microseconds>;

        /**
         * @brief Time point type used for network timing operations
         *
         * Based on the steady clock for consistent timing regardless of system clock
         * adjustments.
         */
        using net_time = mz::time::SteadyTime<std::chrono::microseconds>;

        //------------------------------------------------------------------------
        // ASIO Type Aliases
        //------------------------------------------------------------------------

        /**
         * @brief Alias for the ASIO IO context
         *
         * The core I/O functionality for asynchronous operations.
         */
        using asiocontext = asio::io_context;

        /**
         * @brief Alias for the ASIO work guard
         *
         * Prevents the I/O context from running out of work and stopping.
         */
        using asioguard = asio::executor_work_guard<asio::io_context::executor_type, void, void>;

        /**
         * @brief Alias for the ASIO TCP socket
         *
         * Represents a TCP connection.
         */
        using asiosocket = asio::basic_stream_socket<asio::ip::tcp, asio::io_context::executor_type>;

        /**
         * @brief Alias for the ASIO strand
         *
         * Provides serialized handler execution to prevent concurrency issues.
         */
        using asiostrand = asio::strand<asio::io_context::executor_type>;

        /**
         * @brief Alias for the native socket handle type
         *
         * Platform-specific handle for the underlying socket.
         */
        using asiohandle = asio::basic_socket<asio::ip::tcp, asio::io_context::executor_type>::native_handle_type;

        /**
         * @brief Alias for the ASIO TCP acceptor
         *
         * Used for accepting incoming TCP connections.
         */
        using asioacceptor = asio::basic_socket_acceptor<asio::ip::tcp, asio::io_context::executor_type>;

        /**
         * @brief Alias for the ASIO TCP endpoint
         *
         * Represents an IP address and port.
         */
        using asioendpoint = asio::ip::tcp::endpoint;

        /**
         * @brief Alias for the ASIO resolver results
         *
         * Contains resolved addresses from hostname lookups.
         */
        using asioquery = asio::ip::tcp::resolver::results_type;

        //------------------------------------------------------------------------
        // Endian Conversion Utilities
        //------------------------------------------------------------------------

        /**
         * @brief Converts a value to the network endianness
         *
         * @tparam T The type of value to convert (must satisfy SwapType concept)
         * @param t The value to convert
         * @return T The value converted to network byte order
         *
         * Automatically detects the system's native endianness and performs byte
         * swapping only when necessary.
         */
        template <mz::endian::SwapType T>
        inline T to_endian(T t) noexcept {
            if constexpr (std::endian::native != net_endian) {
                t = mz::endian::swap_bytes(t);
            }
            return t;
        }

        //------------------------------------------------------------------------
        // Forward Declarations
        //------------------------------------------------------------------------

        /**
         * @struct packet_header
         * @brief Header structure for network packets
         *
         * Defined elsewhere, contains metadata for packet routing and processing.
         */
        struct packet_header;

        /**
         * @class packet
         * @brief Represents a network packet
         *
         * Encapsulates data for transmission over the network with header information.
         */
        class packet;

        /**
         * @class connection
         * @brief Represents a network connection
         *
         * Manages the communication channel between network endpoints.
         */
        class connection;

        //------------------------------------------------------------------------
        // Base Encryption Interface
        //------------------------------------------------------------------------

        /**
         * @class encryptor
         * @brief Base class for packet encryption implementations
         *
         * Provides a common interface for encrypting and decrypting network data.
         * Derived classes implement specific encryption algorithms.
         */
        class encryptor
        {
        public:
            /**
             * @brief Encrypts a block of data
             *
             * @param ptr Pointer to the data to encrypt
             * @param size Size of the data in bytes
             * @return int Status code (0 indicates success)
             */
            virtual int encrypt(void* ptr, size_t size) noexcept { return 0; }

            /**
             * @brief Decrypts a block of data
             *
             * @param ptr Pointer to the data to decrypt
             * @param size Size of the data in bytes
             * @return int Status code (0 indicates success)
             */
            virtual int decrypt(void* ptr, size_t size) noexcept { return 0; }
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_CONFIG_HEADER_FILE
