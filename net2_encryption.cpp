/**
 * @file net_encryption.cpp
 * @brief Implementation of network encryption components
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This file contains the implementation of the encryption interfaces defined in
 * net_encryption.h, including BlowFish-based encryption for network connections
 * and the handshake protocols for establishing secure connections.
 */

#include "net2_encryption.h"
#include "net2_server_interface.h"
#include "net2_client_interface.h"
#include "Logger.h"

namespace mz {
    namespace net2 {

        //-----------------------------------------------------------------------------
        // Basic Encryption Interface Implementations
        //-----------------------------------------------------------------------------

        /**
         * @brief Default handshake with client implementation for server
         *
         * Base implementation simply calls the success callback without performing
         * any actual encryption setup. Derived classes should override this with
         * actual encryption handshake logic.
         *
         * @param conn Connection to establish encryption with
         */
        void server_encryption_interface::handshake_with_client(std::shared_ptr<connection> conn) noexcept
        {
            if (!conn) {
                mz::ErrLog.ts() << "server_encryption_interface: Null connection in handshake";
                return;
            }

            // Default implementation just reports success immediately
            m_server_interface.on_handshake_success(std::move(conn));
        }

        /**
         * @brief Default handshake with server implementation for client
         *
         * Base implementation simply calls the success callback without performing
         * any actual encryption setup. Derived classes should override this with
         * actual encryption handshake logic.
         *
         * @param conn Connection to establish encryption with
         */
        void client_encryption_interface::handshake_with_server(std::shared_ptr<connection> conn) noexcept
        {
            if (!conn) {
                mz::ErrLog.ts() << "client_encryption_interface: Null connection in handshake";
                return;
            }

            // Default implementation just reports success immediately
            m_client_interface.on_handshake_success(std::move(conn));
        }

        //-----------------------------------------------------------------------------
        // BlowFish Connection Encryption Implementation
        //-----------------------------------------------------------------------------

        /**
         * @brief Encrypt a packet using BlowFish
         *
         * Encrypts both the header (excluding the length field) and payload
         * of the packet using the BlowFish algorithm.
         *
         * @param p Packet to encrypt
         * @return EncryptionStatus indicating success or specific error
         */
        EncryptionStatus connection_bcrypt::encrypt(packet& p) noexcept
        {
            if (!m_initialized) {
                return EncryptionStatus::KeyNotInitialized;
            }

            try {
                // Encrypt header (excluding size field which is handled separately)
                m_fish.encrypt(p.head_span());

                // Encrypt payload if not empty
                if (!p.empty()) {
                    m_fish.encrypt(p.tail_span());
                }

                return EncryptionStatus::Success;
            }
            catch (...) {
                return EncryptionStatus::AlgorithmFailure;
            }
        }

        /**
         * @brief Decrypt a packet using BlowFish
         *
         * Decrypts both the header (excluding the length field) and payload
         * of the packet using the BlowFish algorithm.
         *
         * @param p Packet to decrypt
         * @return EncryptionStatus indicating success or specific error
         */
        EncryptionStatus connection_bcrypt::decrypt(packet& p) noexcept
        {
            if (!m_initialized) {
                return EncryptionStatus::KeyNotInitialized;
            }

            try {
                // Decrypt header (excluding size field which is handled separately)
                m_fish.decrypt(p.head_span());

                // Decrypt payload if not empty
                if (!p.empty()) {
                    m_fish.decrypt(p.tail_span());
                }

                return EncryptionStatus::Success;
            }
            catch (...) {
                return EncryptionStatus::AlgorithmFailure;
            }
        }

        /**
         * @brief Update encryption parameters using data from a packet
         *
         * Extracts BlowFish parameters from a packet and initializes the
         * encryption engine with them.
         *
         * @param msg Packet containing encryption parameters
         * @return EncryptionStatus indicating success or specific error
         */
        EncryptionStatus connection_bcrypt::update(packet& msg) noexcept
        {
            // Create parameters object to extract into
            mz::crypt::BlowFish::bcrypt_parameters params;

            // Extract parameters from packet, checking for errors
            if (msg.popBack(params.Count) ||
                msg.popBack(params.Salt.span()) ||
                msg.popBack(params.Pass.span()) ||
                msg.size()) {
                return EncryptionStatus::BufferTooSmall;
            }

            // Validate parameters
            if (params.Count > 100000) {
                return EncryptionStatus::InvalidInput;
            }

            try {
                // Initialize encryption with extracted parameters
                m_fish.bcrypt(params.Pass, params.Salt, params.Count);
                m_initialized = true;
                return EncryptionStatus::Success;
            }
            catch (...) {
                m_initialized = false;
                return EncryptionStatus::AlgorithmFailure;
            }
        }

        /**
         * @brief Generate encryption parameters and store in a packet
         *
         * This method is not implemented in the current version.
         *
         * @param p Packet to store parameters in
         * @param rand Random number generator
         * @return EncryptionStatus::NotImplemented
         */
        EncryptionStatus connection_bcrypt::generate(packet& p, mz::Randomizer& rand) noexcept
        {
            // Not implemented in this version
            return EncryptionStatus::AlgorithmFailure;
        }

        //-----------------------------------------------------------------------------
        // BlowFish Server Encryption Implementation
        //-----------------------------------------------------------------------------

        /**
         * @brief Generate encryption parameters for server
         *
         * Creates random encryption parameters for server-side encryption and
         * initializes the encryption engine with them.
         *
         * @return true on success, false on failure
         */
        bool server_bcrypt::generate() noexcept
        {
            try {
                // Create parameters with reasonable defaults
                mz::crypt::BlowFish::bcrypt_parameters params;
                params.Count = 400;  // Good balance of security and performance

                // Generate random values for encryption parameters
                m_rand_engine.randomize(params.Pass.span(), true);
                m_rand_engine.randomize(params.Salt.span(), true);
                m_rand_engine.randomize(m_text.span(), true);

                // Prepare parameter packet for sending to clients
                m_param_packet.clear();
                m_param_packet.pushBack(params.Pass.span());
                m_param_packet.pushBack(params.Salt.span());
                m_param_packet.pushBack(params.Count);
                m_param_packet.pushBack(m_text.span());

                // Initialize server encryption
                m_fish.bcrypt(params);

                // Encrypt the verification text
                m_fish.encrypt(m_text.span());

                return true;
            }
            catch (...) {
                mz::ErrLog.ts() << "server_bcrypt::generate: Failed to create encryption parameters";
                return false;
            }
        }

        /**
         * @brief Perform handshake with a client to establish encryption
         *
         * This method initiates the encryption handshake protocol with a client.
         * The process involves:
         * 1. Setting up encryption for the connection
         * 2. Sending encryption parameters to the client
         * 3. Receiving verification response
         * 4. Verifying the response to confirm successful encryption setup
         *
         * @param conn Connection to perform handshake with
         */
        void server_bcrypt::handshake_with_client(std::shared_ptr<connection> conn) noexcept
        {
            if (!conn) {
                mz::ErrLog.ts() << "server_bcrypt::handshake_with_client: Null connection";
                return;
            }

            try {
                // Create encryption for this connection
                conn->encryptor = std::make_unique<connection_bcrypt>(m_fish);

                // Send encryption parameters to client
                asio::async_write(
                    conn->AsioSocket,
                    m_param_packet.send_array(),
                    [this, conn](std::error_code ec, size_t)
                    {
                        if (!ec) {
                            // Prepare to receive verification response
                            conn->TempMsg.resize(m_text.size());
                            asio::async_read(
                                conn->AsioSocket,
                                conn->TempMsg.recv_array(),
                                [this, conn](std::error_code ec, size_t)
                                {
                                    if (!ec) {
                                        // Verify the response
                                        if (m_text.size() == conn->TempMsg.size() &&
                                            !memcmp(conn->TempMsg.data(), m_text.data(), m_text.size()))
                                        {
                                            // Handshake successful
                                            m_server_interface.on_handshake_success(std::move(conn));
                                        }
                                        else {
                                            // Verification failed
                                            mz::ErrLog.ts() << "server_bcrypt: Incoming message verification failed";
                                            conn->Disconnect();
                                        }
                                    }
                                    else {
                                        // Network error during verification
                                        mz::ErrLog.ts() << "server_bcrypt: Read handshake reply failed: " << ec.message();
                                        conn->Disconnect();
                                    }
                                }
                            );
                        }
                        else {
                            // Network error during parameter send
                            mz::ErrLog.ts() << "server_bcrypt: Write handshake failed: " << ec.message();
                            conn->Disconnect();
                        }
                    });
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts() << "server_bcrypt::handshake_with_client: Exception: " << e.what();
                conn->Disconnect();
            }
            catch (...) {
                mz::ErrLog.ts() << "server_bcrypt::handshake_with_client: Unknown exception";
                conn->Disconnect();
            }
        }

        //-----------------------------------------------------------------------------
        // BlowFish Client Encryption Implementation
        //-----------------------------------------------------------------------------

        /**
         * @brief Perform handshake with a server to establish encryption
         *
         * This method responds to the server's encryption handshake protocol.
         * The process involves:
         * 1. Receiving encryption parameters from the server
         * 2. Setting up encryption using those parameters
         * 3. Sending back verification data to confirm successful setup
         *
         * @param conn Connection to perform handshake with
         */
        void client_bcrypt::handshake_with_server(std::shared_ptr<connection> conn) noexcept
        {
            if (!conn) {
                mz::ErrLog.ts() << "client_bcrypt::handshake_with_server: Null connection";
                return;
            }

            try {
                // Prepare to receive handshake parameters from server
                // Size includes parameters and verification text
                conn->TempMsg.resize(sizeof(mz::crypt::BlowFish::bcrypt_parameters) + sizeof(mz::crypt::BlowPass));

                // Create encryption object for this connection
                conn->encryptor = std::make_unique<connection_bcrypt>();

                // Receive parameters from server
                asio::async_read(
                    conn->AsioSocket,
                    conn->TempMsg.recv_array(),
                    [this, conn](std::error_code ec, size_t)
                    {
                        if (!ec) {
                            try {
                                // Extract verification text
                                mz::crypt::BlowPass code;
                                if (conn->TempMsg.popBack(code.span())) {
                                    throw std::runtime_error("Failed to extract verification text");
                                }

                                // Update encryption with parameters
                                EncryptionStatus status = conn->encryptor->update(conn->TempMsg);
                                if (status == EncryptionStatus::Success)
                                {
                                    // Send verification data back to server
                                    conn->TempMsg.pushBack(code.span());
                                    conn->Send(conn->TempMsg);

                                    // Handshake successful
                                    m_handshake_complete = true;
                                    m_client_interface.on_handshake_success(std::move(conn));
                                }
                                else
                                {
                                    // Parameter processing failed
                                    mz::ErrLog.ts() << "client_bcrypt: Error updating encryption, code = "
                                        << static_cast<int>(status);
                                    conn->Disconnect();
                                }
                            }
                            catch (const std::exception& e) {
                                mz::ErrLog.ts() << "client_bcrypt: Parameter processing exception: " << e.what();
                                conn->Disconnect();
                            }
                        }
                        else {
                            // Network error during parameter receive
                            mz::ErrLog.ts() << "client_bcrypt: Read handshake failed: " << ec.message();
                            conn->Disconnect();
                        }
                    }
                );
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts() << "client_bcrypt::handshake_with_server: Exception: " << e.what();
                conn->Disconnect();
            }
            catch (...) {
                mz::ErrLog.ts() << "client_bcrypt::handshake_with_server: Unknown exception";
                conn->Disconnect();
            }
        }

    } // namespace net2
} // namespace mz
