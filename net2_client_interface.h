/**
 * @file net_client_interface.h
 * @brief Client-side networking interface implementation
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the client_interface class which implements client-side
 * networking functionality for the MZ networking library. It extends the basic_interface
 * class with client-specific operations such as connecting to servers and managing
 * encryption handshakes.
 */

#ifndef MZ_NET_CLIENT_INTERFACE_HEADER_FILE
#define MZ_NET_CLIENT_INTERFACE_HEADER_FILE
#pragma once

#include <string>
#include <memory>

#include "net2_basic_interface.h"
#include "net2_process.h"
#include "net2_encryption.h"

namespace mz {
    namespace net2 {

        /**
         * @class client_interface
         * @brief Client-side network communication interface
         *
         * Extends the basic_interface with capabilities specific to client operations,
         * including connecting to remote servers and managing encryption handshakes.
         */
        class client_interface : public basic_interface {
        public:
            /**
             * @brief Constructor
             *
             * Initializes the client interface with default settings and creates
             * the client-side encryption interface.
             */
            client_interface() : basic_interface{ "CLIENT" } {
                // Create the default client encryption interface
                m_client_encryptor = std::make_unique<client_encryption_interface>(*this);
            }

            /**
             * @brief Disconnect from the server
             *
             * Shorthand for stopping all client operations and disconnecting.
             */
            void disconnect() {
                stop();
            }

            /**
             * @brief Connect to a server
             *
             * Resolves the hostname/IP and attempts to establish a connection.
             *
             * @param host Hostname or IP address of the server
             * @param port Port number to connect to
             */
            void connect(const std::string& host, const uint16_t port) {
                try {
                    // Start the ASIO context if not already running
                    if (!m_asio_thread.joinable()) {
                        start();
                    }

                    // Resolve hostname/IP address into tangible physical address
                    mz::ErrLog.ts(m_name) << "Connecting to " << host << ":" << port;

                    asio::error_code ec;
                    asio::ip::tcp::resolver resolver(m_asio_context);
                    asioquery endpoints = resolver.resolve(host, std::to_string(port), ec);

                    if (!ec) {
                        // Create a new connection object
                        std::shared_ptr<connection> client = std::make_shared<connection>(
                            connection::owner::client,
                            m_asio_context,
                            asiosocket{ m_asio_context },
                            m_incoming_messages,
                            m_random_engine
                        );

                        // Set connection properties
                        client->m_name = m_name;
                        client->m_server = this;

                        // Initiate asynchronous connection
                        asio::async_connect(
                            client->m_asio_socket,
                            endpoints,
                            [this, client](asio::error_code ec, asioendpoint endpoint) {
                                if (!ec) {
                                    mz::ErrLog.ts(m_name) << "Connected to "
                                        << endpoint.address().to_string() << ":"
                                        << endpoint.port();

                                    // Start encryption handshake on the connection's strand
                                    asio::post(
                                        client->m_asio_strand,
                                        [this, client]() {
                                            if (m_client_encryptor) {
                                                m_client_encryptor->handshake_with_server(std::move(client));
                                            }
                                            else {
                                                mz::ErrLog.ts(m_name) << "No client encryptor available";
                                                on_handshake_success(std::move(client));
                                            }
                                        }
                                    );
                                }
                                else {
                                    mz::ErrLog.ts(m_name) << "Connection failed: " << ec.message();
                                    remove_connection(client);
                                }
                            }
                        );

                        // Add to connections list (will be managed even during connection)
                        m_connections.push_back(std::move(client));

                    }
                    else {
                        mz::ErrLog.ts(m_name) << "Resolution failed: " << ec.message();
                    }
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "connect exception: " << e.what();
                }
            }

            /**
             * @brief Handler for successful handshake completion
             *
             * Called when a connection successfully completes the encryption handshake.
             * Starts the connection listening for messages.
             *
             * @param conn Connection that completed handshake
             */
            void on_handshake_success(std::shared_ptr<connection> conn) override {
                if (!conn) {
                    mz::ErrLog.ts(m_name) << "on_handshake_success: Null connection";
                    return;
                }

                try {
                    // Start the connection listening for incoming messages
                    conn->start_listening();

                    mz::ErrLog.ts(m_name) << "Server connection established after handshake";
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "on_handshake_success exception: " << e.what();
                }
            }

        protected:
            /**
             * @brief Process an incoming message
             *
             * Called by update() for each incoming message. Derived classes should
             * override this to implement specific message handling.
             *
             * @param remote Connection that sent the message
             * @param msg The message to process
             */
            void process_message(std::shared_ptr<connection>& remote, packet& msg) override {
                // Default implementation does nothing
                // Derived classes should override this
            }

        public:
            // Client encryption interface
            std::unique_ptr<client_encryption_interface> m_client_encryptor;  ///< Client-side encryption provider
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_CLIENT_INTERFACE_HEADER_FILE

