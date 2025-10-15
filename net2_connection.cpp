/**
 * @file net_connection.cpp
 * @brief Implementation of network connection management
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This file implements the connection class defined in net_connection.h,
 * providing asynchronous I/O operations, message handling, and encryption
 * integration for network connections.
 */

#include "net2_connection.h"
#include "Logger.h"
#include <chrono>

namespace mz {
    namespace net2 {

        /**
         * @brief Destructor implementation
         *
         * Ensures the connection is properly disconnected when destroyed.
         */
        connection::~connection() {
            disconnect();
        }

        /**
         * @brief Start listening for incoming messages
         *
         * Initiates the asynchronous read loop to receive messages.
         */
        void connection::start_listening() {
            try {
                if (is_connected()) {
                    // Start the read loop to receive messages
                    read_loop();
                }
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "start_listening: Exception: " << e.what();
                disconnect();
            }
        }

        /**
         * @brief Stop listening for incoming messages
         *
         * Cancels pending asynchronous operations.
         */
        void connection::stop_listening() {
            try {
                if (is_connected()) {
                    // Cancel any pending async operations
                    m_asio_socket.cancel();
                }
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "stop_listening: Exception: " << e.what();
            }
        }

        /**
         * @brief Disconnect the connection
         *
         * Closes the socket and cleans up resources.
         */
        void connection::disconnect() {
            try {
                if (is_connected()) {
                    // Close the socket with default error code
                    asio::error_code ec;
                    m_asio_socket.close(ec);

                    // Log any errors that occurred during close
                    if (ec) {
                        mz::ErrLog.ts(m_name) << "disconnect: Error closing socket: " << ec.message();
                    }
                }
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "disconnect: Exception: " << e.what();
            }
        }

        /**
         * @brief Loop for sending queued messages
         *
         * Asynchronously sends messages from the send queue.
         */
        void connection::write_loop() noexcept {
            if (!is_connected() || m_send_queue.empty()) {
                return;
            }

            try {
                // Start an asynchronous write operation for the first packet in queue
                asio::async_write(
                    m_asio_socket,
                    m_send_queue.front().send_array(),
                    [this](std::error_code ec, size_t)
                    {
                        if (!ec) {
                            // Successfully sent, remove from queue and update statistics
                            m_send_queue.pop_front();
                            --m_num_outgoing_messages;

                            // Continue with next packet if available
                            if (!m_send_queue.empty()) {
                                write_loop();
                            }
                        }
                        else {
                            // Log error and close connection on failure
                            mz::ErrLog.ts(m_name) << "write_loop: Error: " << ec.message();

                            asio::error_code close_ec;
                            m_asio_socket.close(close_ec);
                        }
                    }
                );
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "write_loop: Exception: " << e.what();
                disconnect();
            }
        }

        /**
         * @brief Loop for receiving messages
         *
         * Asynchronously receives messages from the network.
         */
        void connection::read_loop() noexcept {
            if (!is_connected()) {
                return;
            }

            try {
                // First read the header to determine message size
                asio::async_read(
                    m_asio_socket,
                    m_temp_msg.mbuff_head(),
                    [this](std::error_code ec, std::size_t)
                    {
                        if (!ec) {
                            // Calculate the body length from the header
                            uint32_t body_length = m_temp_msg.get_encoded_size();

                            // Resize the message buffer to accommodate the body
                            m_temp_msg.resize(body_length);

                            if (!m_temp_msg.empty()) {
                                // Read the message body if not empty
                                asio::async_read(
                                    m_asio_socket,
                                    m_temp_msg.mbuff_tail(),
                                    [this](std::error_code ec, std::size_t)
                                    {
                                        if (!ec) {
                                            // Message received successfully
                                            ++m_num_incoming_messages;

                                            // Queue the message for processing
                                            m_server_recv_queue.push_back({
                                                this->shared_from_this(),
                                                m_temp_msg
                                                });

                                            // Continue reading next message
                                            read_loop();
                                        }
                                        else {
                                            // Error reading message body
                                            mz::ErrLog.ts(m_name) << "read_loop: Body error: " << ec.message();
                                            disconnect();
                                        }
                                    }
                                );
                            }
                            else {
                                // Handle empty message (header-only message)
                                ++m_num_incoming_messages;
                                m_server_recv_queue.push_back({
                                    this->shared_from_this(),
                                    m_temp_msg
                                    });

                                // Continue reading next message
                                read_loop();
                            }
                        }
                        else {
                            // Error reading header (could be normal disconnect)
                            if (is_connected()) {
                                mz::ErrLog.ts(m_name) << "read_loop: Header error: " << ec.message();
                                disconnect();
                            }
                        }
                    }
                );
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "read_loop: Exception: " << e.what();
                disconnect();
            }
        }

        /**
         * @brief Send a message over the network
         *
         * Encrypts and queues a message for sending.
         *
         * @param p Message to send
         */
        void connection::send(packet& p) noexcept {
            if (!is_connected()) {
                return;
            }

            try {
                // Increment outgoing message counter
                ++m_num_outgoing_messages;

                // Prepare the packet for network transmission
                p.SwapNetEndian();

                // Encrypt if encryptor is available
                if (m_encryptor) {
                    m_encryptor->encrypt(p);
                }

                // Post to strand to ensure thread safety when queueing message
                asio::post(m_asio_strand, [this, p]() {
                    bool queue_was_empty = m_send_queue.empty();
                    m_send_queue.push_back(p);

                    // Start the write loop if queue was empty
                    if (queue_was_empty) {
                        write_loop();
                    }
                    });
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "send: Exception: " << e.what();
            }
        }

        /**
         * @brief Receive and process a message
         *
         * Processes a message received from the network, including
         * decryption and header processing.
         *
         * @param p Message to process
         * @return Status code (0 = success)
         */
        int connection::receive(packet& p) noexcept {
            try {
                // Decrement incoming message counter
                --m_num_incoming_messages;

                // Decrypt if encryptor is available
                if (m_encryptor) {
                    m_encryptor->decrypt(p);
                }

                // Convert from network byte order
                p.SwapNetEndian();

                // Pass to message handler
                return on_message(p);
            }
            catch (const std::exception& e) {
                mz::ErrLog.ts(m_name) << "receive: Exception: " << e.what();
                return -1;
            }
        }

        /**
         * @brief Get a string representation of the connection
         *
         * @return String with connection details
         */
        std::string connection::string() const {
            try {
                // Get endpoint information if available
                std::string endpoint_info;

                if (is_connected()) {
                    auto remote_endpoint = m_asio_socket.remote_endpoint();
                    endpoint_info = remote_endpoint.address().to_string() + ":" +
                        std::to_string(remote_endpoint.port());
                }
                else {
                    endpoint_info = "not connected";
                }

                // Build info string
                return std::string(m_name + " [" + endpoint_info + "] " +
                    "IN:" + std::to_string(m_num_incoming_messages) +
                    " OUT:" + std::to_string(m_num_outgoing_messages));
            }
            catch (const std::exception&) {
                // Fallback if endpoint information cannot be retrieved
                return m_name + " [?] " +
                    "IN:" + std::to_string(m_num_incoming_messages) +
                    " OUT:" + std::to_string(m_num_outgoing_messages);
            }
        }

        /**
         * @brief Get the current time
         *
         * @return Current time using the network time type
         */
        net_time connection::now() {
            return net_time::now();
        }

    } // namespace net2
} // namespace mz
