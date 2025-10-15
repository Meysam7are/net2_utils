/**
 * @file net_encryption.h
 * @brief Network encryption interfaces and implementations
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the interfaces and implementations for network encryption
 * in the MZ networking library. It provides a layered approach with separate
 * interfaces for connection-level encryption and server/client encryption management.
 */

#ifndef MZ_NET_ENCRYPTION_HEADER_FILE
#define MZ_NET_ENCRYPTION_HEADER_FILE
#pragma once

#include <memory>
#include <type_traits>
#include <string_view>

#include "blow_crypt.h"
#include "net2_packet.h"
#include "Randomizer.h"

namespace mz {
    namespace net2 {

        // Forward declarations
        class server_interface;
        class client_interface;
        class connection;

        /**
         * @enum EncryptionStatus
         * @brief Status codes for encryption operations
         *
         * Provides meaningful return values for encryption operations instead of magic numbers.
         * This improves code clarity and error handling.
         */
        enum class EncryptionStatus : int {
            Success = 0,               ///< Operation completed successfully
            InvalidInput = -1,         ///< Invalid input parameters
            BufferTooSmall = -2,       ///< Output buffer is too small
            KeyNotInitialized = -3,    ///< Encryption key not initialized
            AlgorithmFailure = -4,     ///< Internal algorithm failure
            HandshakeRequired = -5,    ///< Handshake must be completed first
            HandshakeFailure = -6,     ///< Handshake protocol failed
        };

        /**
         * @class connection_encryption_interface
         * @brief Base interface for connection-specific encryption
         *
         * This abstract class defines the interface for encryption mechanisms that can be
         * applied to individual network connections. All encryption operations are marked
         * noexcept to prevent exceptions from escaping, with error codes returned instead.
         */
        class connection_encryption_interface {
        public:
            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup in derived classes.
             */
            virtual ~connection_encryption_interface() noexcept = default;

            /**
             * @brief Encrypt a block of memory
             *
             * @param ptr Pointer to data to encrypt (modified in-place)
             * @param size Size of data in bytes
             * @return true if successful, false on error
             *
             * @note This method performs in-place encryption.
             */
            [[nodiscard]] virtual bool encrypt(void* ptr, size_t size) noexcept {
                return ptr != nullptr && size > 0;
            }

            /**
             * @brief Decrypt a block of memory
             *
             * @param ptr Pointer to data to decrypt (modified in-place)
             * @param size Size of data in bytes
             * @return true if successful, false on error
             *
             * @note This method performs in-place decryption.
             */
            [[nodiscard]] virtual bool decrypt(void* ptr, size_t size) noexcept {
                return ptr != nullptr && size > 0;
            }

            /**
             * @brief Encrypt a memory span
             *
             * @tparam N Size of the span (deduced automatically)
             * @param span Span of bytes to encrypt (modified in-place)
             * @return true if successful, false on error
             */
            template <size_t N>
            [[nodiscard]] bool encrypt(std::span<uint8_t, N> span) noexcept {
                return span.data() != nullptr && span.size() > 0 &&
                    encrypt(span.data(), span.size());
            }

            /**
             * @brief Decrypt a memory span
             *
             * @tparam N Size of the span (deduced automatically)
             * @param span Span of bytes to decrypt (modified in-place)
             * @return true if successful, false on error
             */
            template <size_t N>
            [[nodiscard]] bool decrypt(std::span<uint8_t, N> span) noexcept {
                return span.data() != nullptr && span.size() > 0 &&
                    decrypt(span.data(), span.size());
            }

            /**
             * @brief Encrypt a packet
             *
             * @param p Packet to encrypt (modified in-place)
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] virtual EncryptionStatus encrypt(packet& p) noexcept {
                return EncryptionStatus::Success;
            }

            /**
             * @brief Decrypt a packet
             *
             * @param p Packet to decrypt (modified in-place)
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] virtual EncryptionStatus decrypt(packet& p) noexcept {
                return EncryptionStatus::Success;
            }

            /**
             * @brief Update encryption parameters using data from a packet
             *
             * @param p Packet containing updated parameters
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] virtual EncryptionStatus update(packet& p) noexcept {
                return EncryptionStatus::Success;
            }

            /**
             * @brief Generate encryption parameters and store in a packet
             *
             * @param p Packet to store the generated parameters in
             * @param rand Random number generator to use
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] virtual EncryptionStatus generate(packet& p, mz::Randomizer& rand) noexcept {
                return EncryptionStatus::Success;
            }

            /**
             * @brief Check if the encryption is properly initialized
             *
             * @return true if encryption is ready for use, false otherwise
             */
            [[nodiscard]] virtual bool is_initialized() const noexcept {
                return true;
            }
        };

        /**
         * @class server_encryption_interface
         * @brief Base interface for server-side encryption management
         *
         * This abstract class manages encryption for server instances, particularly
         * handling the server side of the encryption handshake protocol.
         */
        class server_encryption_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param server_interface Reference to the parent server interface
             */
            explicit server_encryption_interface(server_interface& server_interface) noexcept
                : m_server_interface{ server_interface } {
            }

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup in derived classes.
             */
            virtual ~server_encryption_interface() noexcept = default;

            /**
             * @brief Perform a handshake with a client to establish encryption
             *
             * @param conn Connection to perform handshake with
             */
            virtual void handshake_with_client(std::shared_ptr<connection> conn) noexcept = 0;

            /**
             * @brief Create a connection-specific encryptor
             *
             * Factory method that creates encryption objects for individual connections.
             *
             * @param conn Connection that will use the encryptor
             * @return Unique pointer to a new connection encryptor
             */
            [[nodiscard]] virtual std::unique_ptr<connection_encryption_interface>
                create_connection_encryptor(const std::shared_ptr<connection>& conn) noexcept {
                return nullptr;
            }

            /**
             * @brief Set up encryption parameters before any connections
             *
             * @param seed Optional seed for random number generation
             * @return true if successful, false on error
             */
            virtual bool initialize(std::optional<uint32_t> seed = std::nullopt) noexcept {
                return true;
            }

        protected:
            server_interface& m_server_interface;  ///< Reference to the parent server
        };

        /**
         * @class client_encryption_interface
         * @brief Base interface for client-side encryption management
         *
         * This abstract class manages encryption for client instances, particularly
         * handling the client side of the encryption handshake protocol.
         */
        class client_encryption_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param client_interface Reference to the parent client interface
             */
            explicit client_encryption_interface(client_interface& client_interface) noexcept
                : m_client_interface{ client_interface } {
            }

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup in derived classes.
             */
            virtual ~client_encryption_interface() noexcept = default;

            /**
             * @brief Perform a handshake with a server to establish encryption
             *
             * @param conn Connection to perform handshake with
             */
            virtual void handshake_with_server(std::shared_ptr<connection> conn) noexcept = 0;

            /**
             * @brief Create a connection-specific encryptor
             *
             * Factory method that creates encryption objects for the client connection.
             *
             * @param conn Connection that will use the encryptor
             * @return Unique pointer to a new connection encryptor
             */
            [[nodiscard]] virtual std::unique_ptr<connection_encryption_interface>
                create_connection_encryptor(const std::shared_ptr<connection>& conn) noexcept {
                return nullptr;
            }

            /**
             * @brief Check if the encryption handshake has completed successfully
             *
             * @return true if handshake is complete, false otherwise
             */
            [[nodiscard]] virtual bool is_handshake_complete() const noexcept {
                return false;
            }

        protected:
            client_interface& m_client_interface;  ///< Reference to the parent client
        };

        /**
         * @class connection_bcrypt
         * @brief Blowfish implementation of connection encryption
         *
         * This class provides Blowfish encryption for individual connections.
         */
        class alignas(16) connection_bcrypt : public connection_encryption_interface {
        public:
            /**
             * @brief Default constructor
             */
            connection_bcrypt() noexcept = default;

            /**
             * @brief Constructor with pre-initialized BlowFish object
             *
             * @param fish Reference to an initialized BlowFish instance (copied)
             */
            explicit connection_bcrypt(const mz::crypt::BlowFish& fish) noexcept : m_fish{ fish } {
                m_initialized = true;
            }

            /**
             * @brief Destructor
             */
            ~connection_bcrypt() noexcept override = default;

            /**
             * @brief Encrypt a packet
             *
             * @param p Packet to encrypt (modified in-place)
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] EncryptionStatus encrypt(packet& p) noexcept override;

            /**
             * @brief Decrypt a packet
             *
             * @param p Packet to decrypt (modified in-place)
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] EncryptionStatus decrypt(packet& p) noexcept override;

            /**
             * @brief Encrypt a block of memory
             *
             * @param ptr Pointer to data to encrypt (modified in-place)
             * @param size Size of data in bytes
             * @return true if successful, false on error
             */
            [[nodiscard]] bool encrypt(void* ptr, size_t size) noexcept override {
                if (!ptr || size == 0 || !m_initialized) return false;
                try {
                    m_fish.encrypt(ptr, size);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            /**
             * @brief Decrypt a block of memory
             *
             * @param ptr Pointer to data to decrypt (modified in-place)
             * @param size Size of data in bytes
             * @return true if successful, false on error
             */
            [[nodiscard]] bool decrypt(void* ptr, size_t size) noexcept override {
                if (!ptr || size == 0 || !m_initialized) return false;
                try {
                    m_fish.decrypt(ptr, size);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            /**
             * @brief Update encryption parameters using data from a packet
             *
             * @param p Packet containing updated parameters
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] EncryptionStatus update(packet& p) noexcept override;

            /**
             * @brief Generate encryption parameters and store in a packet
             *
             * @param p Packet to store the generated parameters in
             * @param rand Random number generator to use
             * @return EncryptionStatus indicating success or specific error
             */
            [[nodiscard]] EncryptionStatus generate(packet& p, mz::Randomizer& rand) noexcept override;

            /**
             * @brief Check if the encryption is properly initialized
             *
             * @return true if encryption is ready for use, false otherwise
             */
            [[nodiscard]] bool is_initialized() const noexcept override {
                return m_initialized;
            }

            /**
             * @brief Initialize with a given key
             *
             * @param key The encryption key to use
             * @param key_size Size of the key in bytes
             * @return true if successfully initialized, false otherwise
             */
            bool initialize(const void* key, size_t key_size) noexcept {
                if (!key || key_size == 0) return false;
                try {
                    m_fish.init(key, key_size);
                    m_initialized = true;
                    return true;
                }
                catch (...) {
                    m_initialized = false;
                    return false;
                }
            }

            /**
             * @brief Get the underlying BlowFish implementation (for advanced use)
             *
             * @return Reference to the BlowFish object
             */
            [[nodiscard]] const mz::crypt::BlowFish& get_blowfish() const noexcept {
                return m_fish;
            }

            /**
             * @brief Get a mutable reference to the underlying BlowFish (for advanced use)
             *
             * @return Mutable reference to the BlowFish object
             */
            [[nodiscard]] mz::crypt::BlowFish& get_blowfish() noexcept {
                return m_fish;
            }

        private:
            mz::crypt::BlowFish m_fish{};  ///< BlowFish encryption implementation
            bool m_initialized{ false };     ///< Whether the encryption key is initialized
        };

        /**
         * @class server_bcrypt
         * @brief Blowfish implementation of server encryption management
         *
         * This class manages Blowfish encryption for server instances, including
         * handshake protocols and parameter generation.
         */
        class server_bcrypt : public server_encryption_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param server Reference to the parent server interface
             */
            explicit server_bcrypt(server_interface& server) noexcept
                : server_encryption_interface{ server } {
            }

            /**
             * @brief Destructor
             */
            ~server_bcrypt() noexcept override = default;

            /**
             * @brief Generate encryption parameters
             *
             * Creates new encryption keys and parameters for use in handshakes.
             *
             * @return true if successful, false on error
             */
            [[nodiscard]] bool generate() noexcept;

            /**
             * @brief Perform a handshake with a client to establish encryption
             *
             * @param conn Connection to perform handshake with
             */
            void handshake_with_client(std::shared_ptr<connection> conn) noexcept override;

            /**
             * @brief Create a connection-specific encryptor
             *
             * @param conn Connection that will use the encryptor
             * @return Unique pointer to a new connection encryptor
             */
            [[nodiscard]] std::unique_ptr<connection_encryption_interface>
                create_connection_encryptor(const std::shared_ptr<connection>& conn) noexcept override {
                auto encryptor = std::make_unique<connection_bcrypt>(m_fish);
                return encryptor;
            }

            /**
             * @brief Set up encryption parameters before any connections
             *
             * @param seed Optional seed for random number generation
             * @return true if successful, false on error
             */
            bool initialize(std::optional<uint32_t> seed = std::nullopt) noexcept override {
                if (seed) {
                    m_rand_engine.seed(*seed);
                }
                else {
                    m_rand_engine.seed();
                }
                return generate();
            }

        private:
            mz::crypt::BlowFish m_fish{};     ///< Shared BlowFish for server
            mz::crypt::BlowPass m_text{};     ///< Plain text parameters
            mz::crypt::BlowPass m_code{};     ///< Encoded parameters
            packet m_param_packet{};          ///< Packet for sending parameters
            mz::Randomizer m_rand_engine{};   ///< Random number generator
        };

        /**
         * @class client_bcrypt
         * @brief Blowfish implementation of client encryption management
         *
         * This class manages Blowfish encryption for client instances, including
         * handshake protocols and parameter processing.
         */
        class client_bcrypt : public client_encryption_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param client Reference to the parent client interface
             */
            explicit client_bcrypt(client_interface& client) noexcept
                : client_encryption_interface{ client } {
            }

            /**
             * @brief Destructor
             */
            ~client_bcrypt() noexcept override = default;

            /**
             * @brief Perform a handshake with a server to establish encryption
             *
             * @param conn Connection to perform handshake with
             */
            void handshake_with_server(std::shared_ptr<connection> conn) noexcept override;

            /**
             * @brief Create a connection-specific encryptor
             *
             * @param conn Connection that will use the encryptor
             * @return Unique pointer to a new connection encryptor
             */
            [[nodiscard]] std::unique_ptr<connection_encryption_interface>
                create_connection_encryptor(const std::shared_ptr<connection>& conn) noexcept override {
                if (!m_handshake_complete) return nullptr;
                auto encryptor = std::make_unique<connection_bcrypt>(m_fish);
                return encryptor;
            }

            /**
             * @brief Check if the encryption handshake has completed successfully
             *
             * @return true if handshake is complete, false otherwise
             */
            [[nodiscard]] bool is_handshake_complete() const noexcept override {
                return m_handshake_complete;
            }

        private:
            mz::crypt::BlowFish m_fish{};         ///< BlowFish for client
            bool m_handshake_complete{ false };     ///< Handshake completion flag

            /**
             * @brief Process server parameters and initialize encryption
             *
             * @param p Packet containing server parameters
             * @return true if successful, false on error
             */
            bool process_server_parameters(const packet& p) noexcept;
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_ENCRYPTION_HEADER_FILE
