/**
 * @file net_connection.h
 * @brief Network Connection Management
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the connection class which manages individual network
 * connections in the MZ networking library. It provides asynchronous I/O operations,
 * message queueing, and integration with the encryption subsystem.
 */

#ifndef MZ_NET_CONNECTION_HEADER_FILE
#define MZ_NET_CONNECTION_HEADER_FILE
#pragma once

#include <memory>
#include <string>
#include <atomic>

#include "net2_config.h"
#include "net2_safe_queue.h"
#include "net2_encryption.h"
#include "net2_process.h"

namespace mz {
    namespace net2 {

        // Forward declarations
        class basic_interface;
        class server_interface;
        class worker_interface;

        /**
         * @class connection
         * @brief Manages a single network connection
         *
         * The connection class represents a bidirectional network connection and handles
         * all aspects of communication including sending/receiving messages, encryption,
         * and error handling. It uses ASIO for asynchronous I/O operations to prevent blocking.
         *
         * The class inherits from std::enable_shared_from_this to safely create shared
         * pointers to itself when registering callbacks.
         */
        class connection : public std::enable_shared_from_this<connection> {
            friend class basic_interface;

        public:
            /**
             * @enum owner
             * @brief Indicates who owns this connection
             *
             * Used to determine behavior differences between server-side
             * and client-side connections.
             */
            enum class owner {
                server,  ///< Connection owned by server
                client,  ///< Connection owned by client
                worker,  ///< Connection owned by worker
            };

            /**
             * @brief Constructor for server-side connections
             *
             * @param owner_type Type of owner (server/client/worker)
             * @param asio_context ASIO context for I/O operations
             * @param asio_socket Connected socket
             * @param server_recv_queue Queue for incoming messages
             * @param random_engine Random number generator for encryption
             */
            connection(
                owner owner_type,
                asiocontext& asio_context,
                asiosocket asio_socket,
                safe_queue<routed_packet>& server_recv_queue,
                mz::Randomizer& random_engine)
                : m_asio_strand(asio::make_strand(asio_context))
                , m_asio_socket(std::move(asio_socket))
                , m_server_recv_queue(server_recv_queue)
                , m_random_engine(random_engine)
                , m_owner_type(owner_type) {
            }

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup of derived classes.
             */
            virtual ~connection();

            /**
             * @brief Start listening for incoming messages
             *
             * Initiates the asynchronous read loop to receive messages.
             */
            void start_listening();

            /**
             * @brief Stop listening for incoming messages
             *
             * Cancels all pending asynchronous operations.
             */
            void stop_listening();

            /**
             * @brief Check if the connection is active
             *
             * @return true if the socket is open, false if closed
             */
            [[nodiscard]] bool is_connected() const noexcept {
                return m_asio_socket.is_open();
            }

            /**
             * @brief Disconnect the connection
             *
             * Closes the socket and cleans up resources.
             */
            void disconnect();

            /**
             * @brief Receive and process a message
             *
             * Processes a message received from the network, including
             * decryption and header processing.
             *
             * @param p Message to process
             * @return Status code (0 = success)
             */
            int receive(packet& p) noexcept;

            /**
             * @brief Send a message over the network
             *
             * Encrypts and queues a message for sending.
             *
             * @param p Message to send
             */
            void send(packet& p) noexcept;

            /**
             * @brief Receive and process a message (move version)
             *
             * @param p Message to process (will be moved)
             * @return Status code (0 = success)
             */
            int receive(packet&& p) noexcept {
                return receive(p);
            }

            /**
             * @brief Send a message over the network (move version)
             *
             * @param p Message to send (will be moved)
             */
            void send(packet&& p) noexcept {
                send(p);
            }

            /**
             * @brief Handle an incoming message (move version)
             *
             * @param p Message to handle (will be moved)
             * @return Status code (0 = success)
             */
            int on_message(packet&& p) noexcept {
                return on_message(p);
            }

            /**
             * @brief Handle an incoming message
             *
             * Virtual method that can be overridden to customize message handling.
             *
             * @param p Message to handle
             * @return Status code (0 = success)
             */
            virtual int on_message(packet& p) noexcept {
                return 0;
            }

            /**
             * @brief Get a string representation of the connection
             *
             * @return String with connection details
             */
            [[nodiscard]] std::string string() const;

            /**
             * @brief Get the current time
             *
             * @return Current time using the network time type
             */
            [[nodiscard]] net_time now();

        public:
            basic_interface* m_server{ nullptr };                            ///< Parent server interface
            std::unique_ptr<connection_encryption_interface> m_encryptor;  ///< Encryption provider

            // ASIO-specific members
            asio::strand<asiocontext::executor_type> m_asio_strand;        ///< Strand for serialized operations
            asiosocket m_asio_socket;                                      ///< Socket for network I/O
            safe_queue<routed_packet>& m_server_recv_queue;                ///< Queue for incoming messages
            mz::Randomizer& m_random_engine;                               ///< Random number generator

            // Connection properties
            owner m_owner_type{ owner::server };                             ///< Type of owner
            packet m_temp_msg;                                             ///< Temporary message buffer
            safe_queue<packet> m_send_queue;                               ///< Queue for outgoing messages
            std::string m_name{ "CONN" };                                    ///< Connection name/identifier

            // Statistics
            int32_t m_num_outgoing_messages{ 0 };                            ///< Count of sent messages
            int32_t m_num_incoming_messages{ 0 };                            ///< Count of received messages

            // Encryption components
            mz::crypt::BlowFish m_fish;                                    ///< Blowfish encryption
            mz::crypt::BlowPass m_code;                                    ///< Encryption password

        private:
            /**
             * @brief Loop for sending queued messages
             *
             * Asynchronously sends messages from the send queue.
             */
            void write_loop() noexcept;

            /**
             * @brief Loop for receiving messages
             *
             * Asynchronously receives messages from the network.
             */
            void read_loop() noexcept;
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_CONNECTION_HEADER_FILE
