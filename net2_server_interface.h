/**
 * @file net_server_interface.h
 * @brief Server-side networking interface implementation
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the server_interface class which implements server-side
 * networking functionality for the MZ networking library. It extends the basic_interface
 * class with server-specific operations such as connection acceptance, client
 * authentication, and encryption handshaking.
 */

#ifndef MZ_NET_SERVER_INTERFACE_HEADER_FILE
#define MZ_NET_SERVER_INTERFACE_HEADER_FILE
#pragma once

#include "net2_basic_interface.h"
#include "net2_process.h"

namespace mz {
    namespace net2 {

        /**
         * @class server_interface
         * @brief Server-side network communication interface
         *
         * Extends the basic_interface with capabilities specific to server operations,
         * including accepting incoming connections, managing client authentication,
         * and coordinating encryption handshakes.
         */
        class server_interface : public basic_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param port Port number to listen on
             */
            explicit server_interface(uint16_t port) noexcept
                : basic_interface{ "[SERVER]" }
                , m_asio_acceptor(m_asio_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {
                // Create the default server encryption interface
                m_server_encryptor = std::make_unique<server_encryption_interface>(*this);
            }

            /**
             * @brief Start the server
             *
             * Initializes the ASIO context thread and starts accepting connections.
             *
             * @return false on success, true if an error occurred
             */
            bool start() noexcept override {
                try {
                    // Start the ASIO thread
                    m_asio_thread = std::thread([this]() {
                        try {
                            m_asio_context.run();
                        }
                        catch (const std::exception& e) {
                            mz::ErrLog.ts(m_name) << "ASIO thread exception: " << e.what();
                        }
                        });

                    // Begin accepting connections
                    acceptor_loop();

                    mz::ErrLog.ts(m_name) << "Server started on port "
                        << m_asio_acceptor.local_endpoint().port();
                    return false; // Success
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "Start failed: " << e.what();
                    return true; // Error
                }
            }

            /**
             * @brief Stop the server
             *
             * Stops accepting connections and shuts down the interface.
             */
            void stop() noexcept override {
                // Close the acceptor to stop accepting new connections
                m_asio_context.post([this]() {
                    try {
                        asio::error_code ec;
                        m_asio_acceptor.close(ec);

                        if (ec) {
                            mz::ErrLog.ts(m_name) << "Error closing acceptor: " << ec.message();
                        }
                    }
                    catch (const std::exception& e) {
                        mz::ErrLog.ts(m_name) << "Exception closing acceptor: " << e.what();
                    }
                    });

                // Call the base class stop method to clean up
                basic_interface::stop();
            }

            /**
             * @brief Handle client authentication
             *
             * Validates a client after connection establishment but before allowing
             * full message exchange. Derived classes should override this to implement
             * specific authentication logic.
             *
             * @param conn The connection to authenticate
             */
            virtual void authenticate_client(std::shared_ptr<connection> conn) noexcept {
                // Default implementation does nothing
                // Derived classes should override this to implement authentication
            }

            /**
             * @brief Handler for successful handshake completion
             *
             * Called when a connection successfully completes the encryption handshake.
             * Starts the connection listening for messages and adds it to the connections list.
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

                    // Add the connection to our managed connections list
                    m_connections.push_back(std::move(conn));

                    mz::ErrLog.ts(m_name) << "Client connection established after handshake";
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "on_handshake_success exception: " << e.what();
                }
            }

        protected:
            /**
             * @brief ASIO accept loop for incoming connections
             *
             * Asynchronously waits for and accepts incoming connections.
             */
            void acceptor_loop() {
                if (m_stopped) {
                    return;
                }

                try {
                    // Set up asynchronous accept operation
                    m_asio_acceptor.async_accept(
                        [this](std::error_code ec, asiosocket socket) {
                            if (!m_stopped) {
                                if (!ec) {
                                    // Connection accepted successfully
                                    handle_new_connection(std::move(socket));
                                }
                                else {
                                    // Error occurred during accept
                                    mz::ErrLog.ts(m_name) << "Connection accept error: " << ec.message();
                                }

                                // Continue accepting more connections
                                acceptor_loop();
                            }
                        }
                    );
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "acceptor_loop exception: " << e.what();
                }
            }

            /**
             * @brief Handle a newly accepted connection
             *
             * Creates a connection object and initiates the handshake process.
             *
             * @param socket The socket for the new connection
             */
            void handle_new_connection(asiosocket socket) {
                try {
                    // Create a new connection object
                    std::shared_ptr<connection> conn = std::make_shared<connection>(
                        connection::owner::server,
                        m_asio_context,
                        std::move(socket),
                        m_incoming_messages,
                        m_random_engine
                    );

                    // Set the connection name
                    conn->m_name = m_name;
                    conn->m_server = this;

                    // Post the handshake operation to the connection's strand for thread safety
                    asio::post(
                        conn->m_asio_strand,
                        [this, conn]() {
                            // Start the encryption handshake process
                            if (m_server_encryptor) {
                                m_server_encryptor->handshake_with_client(std::move(conn));
                            }
                            else {
                                mz::ErrLog.ts(m_name) << "Server encryptor is null";
                                on_handshake_success(std::move(conn));
                            }
                        }
                    );
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "handle_new_connection exception: " << e.what();
                }
            }

            /**
             * @brief Called when a client has been validated
             *
             * Derived classes should override this to implement specific behavior
             * when a client passes authentication.
             *
             * @param client The validated client connection
             */
            virtual void on_client_validated(std::shared_ptr<connection> client) {
                // Default implementation does nothing
            }

            /**
             * @brief Called when a client has been invalidated
             *
             * Derived classes should override this to implement specific behavior
             * when a client fails authentication or is disconnected.
             *
             * @param client The invalidated client connection
             */
            virtual void on_client_invalidated(std::shared_ptr<connection> client) {
                // Default implementation does nothing
            }

        protected:
            asioacceptor m_asio_acceptor;                                 ///< ASIO acceptor for incoming connections
            std::unique_ptr<server_encryption_interface> m_server_encryptor;  ///< Server-side encryption provider
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_SERVER_INTERFACE_HEADER_FILE

