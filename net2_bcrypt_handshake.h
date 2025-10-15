/**
 * @file net_bcrypt_handshake.h
 * @brief Blowfish encryption handshake protocol implementation
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header defines the bcrypt_handshake structure which implements the
 * Blowfish encryption handshake protocol used by the MZ networking library.
 * It provides methods for generating and processing encryption parameters
 * for secure communication establishment.
 */

#ifndef MZ_NET_BCRYPT_HANDSHAKE_HEADER_FILE
#define MZ_NET_BCRYPT_HANDSHAKE_HEADER_FILE
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

#include "BlowFish.h"
#include "net2_packet.h"
#include "Logger.h"

namespace mz {
    namespace net2 {

        /**
         * @struct bcrypt_handshake
         * @brief Manages the Blowfish encryption handshake protocol
         *
         * This structure encapsulates the state and operations for the Blowfish
         * encryption handshake protocol used to establish secure communications
         * between clients and servers.
         */
        struct bcrypt_handshake {
            mz::crypt::BlowFish m_fish{};              ///< Blowfish encryption engine
            uint32_t m_bcrypt_count{ 400 };              ///< Number of iterations for bcrypt algorithm
            uint32_t m_update_count{ 200 };              ///< Number of iterations for updates
            mz::crypt::BlowSalt m_salt{};              ///< Salt value for encryption
            mz::crypt::BlowPass m_pass{};              ///< Password value for encryption
            mz::crypt::BlowPass m_code{};              ///< Verification code
            packet m_message{};                        ///< Handshake message packet

            /**
             * @brief Generate encryption parameters for handshake
             *
             * This method creates a new set of encryption parameters and prepares
             * a handshake message to be sent to the peer. The process involves:
             *
             * 1. Generating random salt and password values
             * 2. Creating a packet with the encryption parameters
             * 3. Pre-encrypting the parameters with default Blowfish
             * 4. Updating the encryption engine with the parameters
             * 5. Pre-decrypting the packet (since it will be encrypted again when sent)
             *
             * @param random_engine Random number generator for parameter generation
             * @throws std::runtime_error If parameter generation fails
             */
            void generate(mz::Randomizer& random_engine) {
                try {
                    // Reset to initial state
                    m_fish = mz::crypt::BlowFish{};

                    // Generate random salt and password
                    random_engine.randomize(m_salt.span(), true);
                    random_engine.randomize(m_pass.span(), true);

                    // Step 1: Store the parameters in a packet
                    m_message = packet{};
                    m_message.pushBack(m_salt.span());
                    m_message.pushBack(m_pass.span());
                    m_message.pushBack(m_bcrypt_count);
                    m_message.pushBack(m_update_count);

                    // Step 2: Encrypt parameters with initial fish
                    // These will be decrypted on the receiver with initial fish
                    m_fish.encrypt(m_message.tail_span());

                    // Step 3: Use the parameters to update the encryption engine
                    m_fish.bcrypt(m_pass, m_salt, m_bcrypt_count);

                    // Step 4: Now decrypt the message since upon send it will be encrypted again
                    m_fish.decrypt(m_message.tail_span());

                    mz::ErrLog.ts() << "Generated handshake parameters (BcryptCount: "
                        << m_bcrypt_count << ", UpdateCount: " << m_update_count << ")";
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts() << "Failed to generate handshake parameters: " << e.what();
                    throw std::runtime_error("Handshake parameter generation failed");
                }
            }

            /**
             * @brief Update encryption parameters from received packet
             *
             * This method extracts encryption parameters from a received packet
             * and updates the encryption engine accordingly. The process involves:
             *
             * 1. Extracting salt, password, and iteration counts from the packet
             * 2. Updating the encryption engine with the extracted parameters
             *
             * @param packet Received packet containing encryption parameters
             * @return true if update was successful, false otherwise
             * @throws std::runtime_error If parameter extraction fails
             */
            bool update(packet& p) {
                try {
                    // Reset to initial state
                    m_fish = mz::crypt::BlowFish{};

                    // Extract parameters in reverse order of insertion
                    if (p.popBack(m_update_count) ||
                        p.popBack(m_bcrypt_count) ||
                        p.popBack(m_pass.span()) ||
                        p.popBack(m_salt.span())) {

                        mz::ErrLog.ts() << "Failed to extract handshake parameters from packet";
                        return false;
                    }

                    // Validate parameters
                    if (m_bcrypt_count > 10000 || m_update_count > 10000) {
                        mz::ErrLog.ts() << "Invalid handshake parameters: count values too high";
                        return false;
                    }

                    mz::ErrLog.ts() << "Received handshake parameters (BcryptCount: "
                        << m_bcrypt_count << ", UpdateCount: " << m_update_count << ")";

                    // Update encryption engine with parameters
                    m_fish.bcrypt(m_pass, m_salt, m_bcrypt_count);

                    return true;
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts() << "Failed to update handshake parameters: " << e.what();
                    throw std::runtime_error("Handshake parameter update failed");
                }
            }

            /**
             * @brief Verify the handshake with a received verification code
             *
             * Checks if the received verification code matches the expected code,
             * confirming that both sides have established the same encryption parameters.
             *
             * @param received_code The verification code received from peer
             * @return true if verification succeeds, false otherwise
             */
            bool verify(const mz::crypt::BlowPass& received_code) const noexcept {
                try {
                    return (received_code == m_code);
                }
                catch (...) {
                    return false;
                }
            }

            /**
             * @brief Generate a verification code
             *
             * Creates a random verification code that can be sent to the peer
             * for handshake verification.
             *
             * @param random_engine Random number generator for code generation
             */
            void generate_verification_code(mz::Randomizer& random_engine) noexcept {
                try {
                    random_engine.randomize(m_code.span(), true);
                }
                catch (const std::exception& e) {
                    mz::ErrLog.ts() << "Failed to generate verification code: " << e.what();
                }
            }

            /**
             * @brief Encrypt a message using the established parameters
             *
             * @param data Pointer to data to encrypt
             * @param size Size of data in bytes
             * @return true if encryption succeeded, false otherwise
             */
            bool encrypt(void* data, size_t size) noexcept {
                if (!data || size == 0) return false;

                try {
                    m_fish.encrypt(data, size);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }

            /**
             * @brief Decrypt a message using the established parameters
             *
             * @param data Pointer to data to decrypt
             * @param size Size of data in bytes
             * @return true if decryption succeeded, false otherwise
             */
            bool decrypt(void* data, size_t size) noexcept {
                if (!data || size == 0) return false;

                try {
                    m_fish.decrypt(data, size);
                    return true;
                }
                catch (...) {
                    return false;
                }
            }
        };

    } // namespace net2
} // namespace mz

#endif // MZ_NET_BCRYPT_HANDSHAKE_HEADER_FILE


