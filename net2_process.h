/**
 * @file net_process.h
 * @brief Network Message Processing Framework
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the interfaces for processing network messages within the MZ
 * networking library. It provides a flexible framework for handling different types
 * of messages, including specialized handlers for connection handshakes.
 */

#ifndef MZ_NET_PROCESS_HEADER_FILE
#define MZ_NET_PROCESS_HEADER_FILE
#pragma once

#include <memory>
#include <functional>
#include <string>
#include <unordered_map>

#include "net2_packet.h"

namespace mz {
    namespace net2 {

        // Forward declarations
        class basic_server;

        /**
         * @enum ProcessResult
         * @brief Result codes for message processing operations
         *
         * Provides meaningful return values for process operations to indicate
         * success, failure, or specific handling instructions.
         */
        enum class ProcessResult : int {
            Success = 0,               ///< Message was processed successfully
            NotHandled = 1,            ///< Message was not handled by this processor
            Error = -1,                ///< An error occurred during processing
            ConnectionClosed = -2,     ///< The connection should be closed
            Retry = 2,                 ///< The message should be retried later
            ForwardMessage = 3,        ///< The message should be forwarded to another handler
        };

        /**
         * @class basic_process
         * @brief Base class for network message processors
         *
         * This abstract class defines the interface for objects that process network messages.
         * Each processor is associated with a specific connection and handles messages
         * that come in through that connection.
         */
        class basic_process {
        public:
            /**
             * @brief Constructor
             *
             * @param connection Connection that this processor is associated with
             */
            explicit basic_process(std::shared_ptr<connection> connection) noexcept
                : m_connection{ std::move(connection) } {
            }

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup in derived classes.
             */
            virtual ~basic_process() noexcept = 0;

            /**
             * @brief Process an incoming message
             *
             * @param message The message to process
             * @return ProcessResult indicating the result of processing
             *
             * This is the main message handling method that derived classes should implement.
             */
            [[nodiscard]] virtual ProcessResult on_message(packet& message) noexcept {
                return ProcessResult::NotHandled;
            }

            /**
             * @brief Get the associated connection
             *
             * @return A shared pointer to the connection
             */
            [[nodiscard]] std::shared_ptr<connection> get_connection() const noexcept {
                return m_connection;
            }

            /**
             * @brief Initialize the processor
             *
             * Called after construction to perform any necessary setup that couldn't
             * be done in the constructor.
             *
             * @return true if initialization was successful, false otherwise
             */
            virtual bool initialize() noexcept {
                return true;
            }

            /**
             * @brief Check if this processor can handle a specific message type
             *
             * @param command The command or message type to check
             * @return true if this processor can handle the message type, false otherwise
             */
            [[nodiscard]] virtual bool can_handle(uint32_t command) const noexcept {
                return false;
            }

            /**
             * @brief Get the name of this processor
             *
             * @return String view containing the processor name
             */
            [[nodiscard]] virtual std::string_view get_name() const noexcept {
                return "basic_process";
            }

        protected:
            std::shared_ptr<connection> m_connection;  ///< Connection this processor is associated with

            /**
             * @brief Helper method to send a response message
             *
             * @param response The packet to send as a response
             * @return true if the message was sent successfully, false otherwise
             */
            bool send_response(packet& response) noexcept {
                if (!m_connection) return false;

                try {
                    m_connection->Send(response);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            /**
             * @brief Log an error related to message processing
             *
             * @param message Error message to log
             */
            void log_error(const std::string& message) noexcept;
        };

        // Implement the pure virtual destructor inline to avoid linker errors
        inline basic_process::~basic_process() noexcept = default;

        /**
         * @class basic_server_handshake
         * @brief Special processor for handling server handshake messages
         *
         * This class handles the server side of the connection handshake protocol,
         * which typically involves authentication and encryption setup.
         */
        class basic_server_handshake : public basic_process {
        public:
            /**
             * @brief Constructor
             *
             * @param connection Connection that this processor is associated with
             * @param server Pointer to the server that owns this connection
             */
            basic_server_handshake(std::shared_ptr<connection> connection, basic_server* server) noexcept
                : basic_process{ std::move(connection) }, m_server{ server } {
            }

            /**
             * @brief Destructor
             */
            ~basic_server_handshake() noexcept override = default;

            /**
             * @brief Process an incoming handshake message
             *
             * @param message The handshake message to process
             * @return ProcessResult indicating the result of handshake processing
             */
            [[nodiscard]] ProcessResult on_message(packet& message) noexcept override;

            /**
             * @brief Check if this processor can handle a specific message type
             *
             * @param command The command or message type to check
             * @return true if this processor can handle the message type, false otherwise
             */
            [[nodiscard]] bool can_handle(uint32_t command) const noexcept override;

            /**
             * @brief Get the name of this processor
             *
             * @return String view containing the processor name
             */
            [[nodiscard]] std::string_view get_name() const noexcept override {
                return "server_handshake";
            }

            /**
             * @brief Start the handshake process
             *
             * Initiates the handshake protocol by sending the initial handshake message.
             *
             * @return true if handshake was initiated successfully, false otherwise
             */
            [[nodiscard]] bool start_handshake() noexcept;

            /**
             * @brief Check if the handshake is complete
             *
             * @return true if the handshake has completed successfully, false otherwise
             */
            [[nodiscard]] bool is_handshake_complete() const noexcept {
                return m_handshake_complete;
            }

        protected:
            basic_server* m_server{ nullptr };        ///< Server that owns this connection
            bool m_handshake_complete{ false };       ///< Flag indicating handshake completion
            uint32_t m_handshake_stage{ 0 };          ///< Current stage of the handshake process

            /**
             * @brief Process the initial handshake message
             *
             * @param message The initial handshake message
             * @return ProcessResult indicating the result of processing
             */
            [[nodiscard]] ProcessResult process_initial_handshake(packet& message) noexcept;

            /**
             * @brief Process the authentication message
             *
             * @param message The authentication message
             * @return ProcessResult indicating the result of processing
             */
            [[nodiscard]] ProcessResult process_authentication(packet& message) noexcept;

            /**
             * @brief Process the encryption setup message
             *
             * @param message The encryption setup message
             * @return ProcessResult indicating the result of processing
             */
            [[nodiscard]] ProcessResult process_encryption_setup(packet& message) noexcept;

            /**
             * @brief Process the final handshake confirmation
             *
             * @param message The final confirmation message
             * @return ProcessResult indicating the result of processing
             */
            [[nodiscard]] ProcessResult process_final_confirmation(packet& message) noexcept;
        };

        /**
         * @class processor_factory
         * @brief Factory for creating message processors
         *
         * This class provides a centralized way to create appropriate message processors
         * based on message types and connection states.
         */
        class processor_factory {
        public:
            /**
             * @brief Create a processor for a specific connection and message type
             *
             * @param connection Connection that needs a processor
             * @param command_type The type of message to be processed
             * @param server Optional server context for server-side processing
             * @return Unique pointer to the created processor, or nullptr if no suitable processor exists
             */
            [[nodiscard]] static std::unique_ptr<basic_process> create_processor(
                std::shared_ptr<connection> connection,
                uint32_t command_type,
                basic_server* server = nullptr) noexcept;

            /**
             * @brief Register a processor creation function for a specific message type
             *
             * @param command_type The message type this processor handles
             * @param creator Function that creates a processor for this message type
             */
            static void register_processor(uint32_t command_type,
                std::function<std::unique_ptr<basic_process>(
                    std::shared_ptr<connection>,
                    basic_server*)> creator) noexcept;

        private:
            /// Map of message types to processor creation functions
            static std::unordered_map<uint32_t,
                std::function<std::unique_ptr<basic_process>(
                    std::shared_ptr<connection>,
                    basic_server*)>> s_processor_registry;
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_PROCESS_HEADER_FILE
