/**
 * @file net_basic_interface.h
 * @brief Base networking interface for client and server implementations
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the basic_interface class which serves as the foundation
 * for both client and server network interfaces in the MZ networking library.
 * It provides common functionality for managing connections, message processing,
 * and asynchronous operations.
 */

#ifndef MZ_BASIC_INTERFACE_HEADER_FILE
#define MZ_BASIC_INTERFACE_HEADER_FILE
#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <deque>
#include <algorithm>

#include "net2_connection.h"
#include "net2_encryption.h"
#include "Logger.h"

namespace mz {
    namespace net2 {

        /**
         * @class basic_interface
         * @brief Base class for network communication interfaces
         *
         * This abstract class provides the foundation for both client and server
         * implementations in the network library. It manages the ASIO context,
         * connections, and message processing loop.
         */
        class basic_interface {
        public:
            /**
             * @brief Constructor
             *
             * @param name Identifier for this interface (used in logging)
             */
            explicit basic_interface(const std::string& name)
                : m_name{ name }
                , m_asio_guard{ asio::make_work_guard(m_asio_context) } {
            }

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup of derived classes by stopping the interface.
             */
            virtual ~basic_interface() {
                stop();
            }

            /**
             * @brief Start the interface
             *
             * Initializes the ASIO context thread to handle asynchronous operations.
             *
             * @return false on success, true if an error occurred
             */
            virtual bool start() noexcept {
                try {
                    // Run ASIO I/O context in a separate thread
                    m_asio_thread = std::thread([this]() {
                        try {
                            m_asio_context.run();
                        }
                        catch (const std::exception& e) {
                            mz::ErrLog.ts(m_name) << "ASIO thread exception: " << e.what();
                        }
                        });

                    mz::ErrLog.ts(m_name) << "Interface started successfully";
                    return false; // Success
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "Start failed: " << e.what();
                    return true; // Error
                }
            }

            /**
             * @brief Stop the interface
             *
             * Stops the ASIO context and joins the thread.
             */
            virtual void stop() noexcept {
                if (!m_stopped) {
                    m_stopped = true;

                    try {
                        // Clear all connections safely through the ASIO context
                        m_asio_context.post([this]() {
                            m_connections.clear();
                            });

                        // Stop the ASIO context
                        m_asio_context.post([this]() {
                            m_asio_context.stop();
                            });

                        // Join the ASIO thread
                        if (m_asio_thread.joinable()) {
                            m_asio_thread.join();
                        }

                        mz::ErrLog.ts(m_name) << "Interface stopped";
                    }
                    catch (const std::exception& e) {
                        mz::ErrLog.ts(m_name) << "Stop exception: " << e.what();
                    }
                }
            }

            /**
             * @brief Remove a connection from the interface
             *
             * @param client Connection to remove
             */
            virtual void remove_connection(std::shared_ptr<connection> client) noexcept {
                if (!client) {
                    return;
                }

                try {
                    // Release our reference to the connection
                    client.reset();

                    // Remove from the connections list
                    m_connections.erase(
                        std::remove(m_connections.begin(), m_connections.end(), client),
                        m_connections.end()
                    );
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "remove_connection exception: " << e.what();
                }
            }

            /**
             * @brief Process incoming messages
             *
             * Processes up to the specified number of messages from the incoming queue.
             *
             * @param max_messages Maximum number of messages to process
             * @param wait Whether to wait for messages if the queue is empty
             */
            void update(size_t max_messages, bool wait) noexcept {
                if (m_stopped) {
                    return;
                }

                try {
                    // Wait for messages if requested
                    if (wait && m_incoming_messages.empty()) {
                        m_incoming_messages.wait();
                    }

                    // Process messages up to the specified limit
                    size_t message_count = 0;
                    while (message_count < max_messages && !m_incoming_messages.empty()) {
                        // Get next message
                        auto message = m_incoming_messages.pop_front();

                        // Update connection statistics
                        if (message.remote) {
                            message.remote->m_num_incoming_messages--;

                            // Process the message - derived classes should implement this
                            process_message(message.remote, message.msg);
                        }

                        message_count++;
                    }
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts(m_name) << "update exception: " << e.what();
                }
            }

            /**
             * @brief Handler for successful handshake completion
             *
             * Called when a connection successfully completes the encryption handshake.
             * Derived classes should override this to implement specific behavior.
             *
             * @param conn Connection that completed handshake
             */
            virtual void on_handshake_success(std::shared_ptr<connection> conn) {
                if (conn) {
                    mz::ErrLog.ts(m_name) << "Handshake completed with " << conn->string();
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
            virtual void process_message(
                std::shared_ptr<connection>& remote,
                packet& msg) {
                // Base implementation does nothing
                // Derived classes should override this
            }

        public: // Protected data members
            safe_queue<routed_packet> m_incoming_messages;              ///< Queue of incoming messages
            std::deque<std::shared_ptr<connection>> m_connections;      ///< Active connections
            asiocontext m_asio_context;                                 ///< ASIO I/O context
            std::thread m_asio_thread;                                  ///< Thread for ASIO operations
            asioguard m_asio_guard;                                     ///< Keeps ASIO context alive
            std::atomic<bool> m_stopped{ false };                         ///< Interface stop flag
            std::string m_name;                                         ///< Interface identifier
            mz::Randomizer m_random_engine;                             ///< Random number generator
        };

    } // namespace net2
} // namespace mz

#endif // MZ_BASIC_INTERFACE_HEADER_FILE

