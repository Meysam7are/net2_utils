/**
 * @file net_safe_queue.h
 * @brief Thread-safe queue implementation for networking components
 * @author Meysam Zare
 * @copyright Copyright (c) 2021-2024 Meysam Zare. All rights reserved.
 *
 * This header provides a thread-safe queue implementation that supports both blocking
 * and non-blocking operations. It's designed to facilitate safe communication between
 * threads in networking contexts, particularly for message passing between connection
 * handlers and processing threads.
 */

#ifndef NET_SAFE_QUEUE_HEADER_FILE
#define NET_SAFE_QUEUE_HEADER_FILE
#pragma once

#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <optional>
#include <utility>

#include "net2_packet.h"

namespace mz {
    namespace net2 {

        /**
         * @class safe_queue
         * @brief A thread-safe queue implementation with blocking capabilities
         * @tparam T The type of elements stored in the queue
         *
         * This template class provides a thread-safe wrapper around std::deque with
         * additional synchronization features. It supports operations at both ends
         * of the queue (front and back) and provides mechanisms for threads to wait
         * for items to become available.
         */
        template<typename T>
        class safe_queue
        {
        public:
            /**
             * @name Constructors and Destructors
             * @{
             */

             /**
              * @brief Default constructor
              *
              * Creates an empty queue with default capacity settings.
              */
            safe_queue() noexcept = default;

            /**
             * @brief Constructor with maximum capacity
             * @param max_capacity Maximum number of items the queue can hold (0 = unlimited)
             */
            explicit safe_queue(size_t max_capacity) noexcept
                : m_capacity(max_capacity) {
            }

            /**
             * @brief Copy constructor (deleted)
             *
             * Queue cannot be copied as it would break thread safety guarantees.
             */
            safe_queue(const safe_queue<T>&) = delete;

            /**
             * @brief Move constructor (deleted)
             *
             * Queue cannot be moved as it would break thread safety guarantees.
             */
            safe_queue(safe_queue<T>&&) = delete;

            /**
             * @brief Copy assignment operator (deleted)
             *
             * Queue cannot be copied as it would break thread safety guarantees.
             */
            safe_queue& operator=(const safe_queue<T>&) = delete;

            /**
             * @brief Move assignment operator (deleted)
             *
             * Queue cannot be moved as it would break thread safety guarantees.
             */
            safe_queue& operator=(safe_queue<T>&&) = delete;

            /**
             * @brief Virtual destructor
             *
             * Ensures proper cleanup of derived classes. Clears the queue before destruction.
             */
            virtual ~safe_queue() { clear(); }
            /** @} */

            /**
             * @name Basic Queue Operations
             * @{
             */

             /**
              * @brief Get a reference to the item at the front of the queue
              * @return Reference to the front item
              * @warning Undefined behavior if the queue is empty
              */
            [[nodiscard]] T& front()
            {
                std::scoped_lock lock(m_mutex);
                return m_queue.front();
            }

            /**
             * @brief Get a const reference to the item at the front of the queue
             * @return Const reference to the front item
             * @warning Undefined behavior if the queue is empty
             */
            [[nodiscard]] const T& front() const
            {
                std::scoped_lock lock(m_mutex);
                return m_queue.front();
            }

            /**
             * @brief Get a reference to the item at the back of the queue
             * @return Reference to the back item
             * @warning Undefined behavior if the queue is empty
             */
            [[nodiscard]] const T& back()
            {
                std::scoped_lock lock(m_mutex);
                return m_queue.back();
            }

            /**
             * @brief Get a const reference to the item at the back of the queue
             * @return Const reference to the back item
             * @warning Undefined behavior if the queue is empty
             */
            [[nodiscard]] const T& back() const
            {
                std::scoped_lock lock(m_mutex);
                return m_queue.back();
            }

            /**
             * @brief Remove and return the item from the front of the queue
             * @return The front item (moved)
             * @warning Undefined behavior if the queue is empty
             */
            T pop_front()
            {
                std::scoped_lock lock(m_mutex);
                auto item = std::move(m_queue.front());
                m_queue.pop_front();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return item;
            }

            /**
             * @brief Remove and return the item from the back of the queue
             * @return The back item (moved)
             * @warning Undefined behavior if the queue is empty
             */
            T pop_back()
            {
                std::scoped_lock lock(m_mutex);
                auto item = std::move(m_queue.back());
                m_queue.pop_back();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return item;
            }

            /**
             * @brief Add an item to the back of the queue (lvalue version)
             * @param item The item to add
             * @return true if successful, false if the queue is full
             */
            bool push_back(const T& item)
            {
                {
                    std::scoped_lock lock(m_mutex);
                    if (m_capacity > 0 && m_queue.size() >= m_capacity)
                        return false;

                    m_queue.emplace_back(item);
                    m_count.fetch_add(1, std::memory_order_relaxed);
                }

                // Notify waiting threads
                m_condition.notify_one();
                return true;
            }

            /**
             * @brief Add an item to the back of the queue (rvalue version)
             * @param item The item to add (will be moved)
             * @return true if successful, false if the queue is full
             */
            bool push_back(T&& item)
            {
                {
                    std::scoped_lock lock(m_mutex);
                    if (m_capacity > 0 && m_queue.size() >= m_capacity)
                        return false;

                    m_queue.emplace_back(std::move(item));
                    m_count.fetch_add(1, std::memory_order_relaxed);
                }

                // Notify waiting threads
                m_condition.notify_one();
                return true;
            }

            /**
             * @brief Add an item to the front of the queue (lvalue version)
             * @param item The item to add
             * @return true if successful, false if the queue is full
             */
            bool push_front(const T& item)
            {
                {
                    std::scoped_lock lock(m_mutex);
                    if (m_capacity > 0 && m_queue.size() >= m_capacity)
                        return false;

                    m_queue.emplace_front(item);
                    m_count.fetch_add(1, std::memory_order_relaxed);
                }

                // Notify waiting threads
                m_condition.notify_one();
                return true;
            }

            /**
             * @brief Add an item to the front of the queue (rvalue version)
             * @param item The item to add (will be moved)
             * @return true if successful, false if the queue is full
             */
            bool push_front(T&& item)
            {
                {
                    std::scoped_lock lock(m_mutex);
                    if (m_capacity > 0 && m_queue.size() >= m_capacity)
                        return false;

                    m_queue.emplace_front(std::move(item));
                    m_count.fetch_add(1, std::memory_order_relaxed);
                }

                // Notify waiting threads
                m_condition.notify_one();
                return true;
            }
            /** @} */

            /**
             * @name Try Operations (Non-blocking)
             * @{
             */

             /**
              * @brief Try to get and remove an item from the front of the queue
              * @param[out] item Where to store the popped item
              * @return true if an item was popped, false if the queue was empty
              */
            bool try_pop_front(T& item)
            {
                std::scoped_lock lock(m_mutex);
                if (m_queue.empty())
                    return false;

                item = std::move(m_queue.front());
                m_queue.pop_front();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return true;
            }

            /**
             * @brief Try to get and remove an item from the back of the queue
             * @param[out] item Where to store the popped item
             * @return true if an item was popped, false if the queue was empty
             */
            bool try_pop_back(T& item)
            {
                std::scoped_lock lock(m_mutex);
                if (m_queue.empty())
                    return false;

                item = std::move(m_queue.back());
                m_queue.pop_back();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return true;
            }

            /**
             * @brief Try to get the front item without removing it
             * @return Optional containing the item, or empty optional if queue is empty
             */
            std::optional<T> try_front() const
            {
                std::scoped_lock lock(m_mutex);
                if (m_queue.empty())
                    return std::nullopt;
                return m_queue.front();
            }

            /**
             * @brief Try to get the back item without removing it
             * @return Optional containing the item, or empty optional if queue is empty
             */
            std::optional<T> try_back() const
            {
                std::scoped_lock lock(m_mutex);
                if (m_queue.empty())
                    return std::nullopt;
                return m_queue.back();
            }
            /** @} */

            /**
             * @name Batch Operations
             * @{
             */

             /**
              * @brief Add multiple items to the back of the queue
              * @tparam InputIt Input iterator type
              * @param begin Iterator to the first item
              * @param end Iterator past the last item
              * @return Number of items successfully added
              */
            template<typename InputIt>
            size_t push_back_batch(InputIt begin, InputIt end)
            {
                size_t added = 0;
                {
                    std::scoped_lock lock(m_mutex);
                    size_t available = (m_capacity > 0) ?
                        std::max<size_t>(0, m_capacity - m_queue.size()) :
                        std::numeric_limits<size_t>::max();

                    for (auto it = begin; it != end && added < available; ++it, ++added) {
                        m_queue.emplace_back(*it);
                    }

                    if (added > 0)
                        m_count.fetch_add(added, std::memory_order_relaxed);
                }

                if (added > 0)
                    m_condition.notify_all();
                return added;
            }

            /**
             * @brief Remove and return multiple items from the front of the queue
             * @param max_items Maximum number of items to pop
             * @return Vector containing the popped items
             */
            std::vector<T> pop_front_batch(size_t max_items)
            {
                std::vector<T> result;

                std::scoped_lock lock(m_mutex);
                size_t to_pop = std::min(max_items, m_queue.size());

                result.reserve(to_pop);
                for (size_t i = 0; i < to_pop; ++i) {
                    result.emplace_back(std::move(m_queue.front()));
                    m_queue.pop_front();
                }

                if (to_pop > 0)
                    m_count.fetch_sub(to_pop, std::memory_order_relaxed);

                return result;
            }
            /** @} */

            /**
             * @name Status Operations
             * @{
             */

             /**
              * @brief Check if the queue is empty
              * @return true if the queue contains no items, false otherwise
              */
            [[nodiscard]] bool empty() const noexcept
            {
                // Fast check using atomic counter
                if (m_count.load(std::memory_order_relaxed) > 0)
                    return false;

                // Double-check with lock for consistency
                std::scoped_lock lock(m_mutex);
                return m_queue.empty();
            }

            /**
             * @brief Get the number of items in the queue
             * @return Current item count
             */
            [[nodiscard]] size_t count() const noexcept
            {
                return m_count.load(std::memory_order_relaxed);
            }

            /**
             * @brief Get the size of the queue
             * @return Current item count (same as count())
             */
            [[nodiscard]] size_t size() const noexcept
            {
                return count();
            }

            /**
             * @brief Check if the queue is full
             * @return true if the queue is at capacity, false otherwise
             * @note Always returns false if the queue has no capacity limit
             */
            [[nodiscard]] bool full() const noexcept
            {
                if (m_capacity == 0)
                    return false;

                return count() >= m_capacity;
            }

            /**
             * @brief Get the maximum capacity of the queue
             * @return Maximum number of items the queue can hold (0 = unlimited)
             */
            [[nodiscard]] size_t capacity() const noexcept
            {
                return m_capacity;
            }

            /**
             * @brief Set the maximum capacity of the queue
             * @param new_capacity New maximum capacity (0 = unlimited)
             * @note This will not remove items if the queue is already over capacity
             */
            void set_capacity(size_t new_capacity) noexcept
            {
                m_capacity = new_capacity;
            }

            /**
             * @brief Remove all items from the queue
             */
            void clear()
            {
                std::scoped_lock lock(m_mutex);
                m_queue.clear();
                m_count.store(0, std::memory_order_relaxed);
            }
            /** @} */

            /**
             * @name Waiting Operations
             * @{
             */

             /**
              * @brief Wait until the queue has at least one item
              *
              * Blocks the current thread until an item becomes available.
              */
            void wait()
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_condition.wait(lock, [this]() { return !m_queue.empty(); });
            }

            /**
             * @brief Wait until the queue has at least one item, with timeout
             * @tparam Rep Clock tick representation type
             * @tparam Period Clock tick period
             * @param timeout Maximum duration to wait
             * @return true if an item is available, false if the timeout was reached
             */
            template<typename Rep, typename Period>
            bool wait_for(const std::chrono::duration<Rep, Period>& timeout)
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                return m_condition.wait_for(lock, timeout, [this]() { return !m_queue.empty(); });
            }

            /**
             * @brief Wait until the queue has at least one item, or until a specific time
             * @tparam Clock Clock type
             * @tparam Duration Duration type
             * @param deadline Time point to wait until
             * @return true if an item is available, false if the deadline was reached
             */
            template<typename Clock, typename Duration>
            bool wait_until(const std::chrono::time_point<Clock, Duration>& deadline)
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                return m_condition.wait_until(lock, deadline, [this]() { return !m_queue.empty(); });
            }

            /**
             * @brief Wait and pop an item from the front of the queue
             * @return The front item (moved)
             *
             * This method combines waiting and popping in one atomic operation,
             * which is more efficient and safer than calling wait() and pop_front() separately.
             */
            T wait_and_pop_front()
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                m_condition.wait(lock, [this]() { return !m_queue.empty(); });

                auto item = std::move(m_queue.front());
                m_queue.pop_front();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return item;
            }

            /**
             * @brief Wait and pop an item from the front of the queue, with timeout
             * @tparam Rep Clock tick representation type
             * @tparam Period Clock tick period
             * @param timeout Maximum duration to wait
             * @return Optional containing the popped item, or empty if timeout was reached
             */
            template<typename Rep, typename Period>
            std::optional<T> wait_and_pop_front_for(const std::chrono::duration<Rep, Period>& timeout)
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                if (!m_condition.wait_for(lock, timeout, [this]() { return !m_queue.empty(); }))
                    return std::nullopt;

                auto item = std::move(m_queue.front());
                m_queue.pop_front();
                m_count.fetch_sub(1, std::memory_order_relaxed);
                return item;
            }
            /** @} */

        protected:
            mutable std::mutex m_mutex;               ///< Mutex for thread-safe access to the queue
            std::deque<T> m_queue;                    ///< The underlying queue container
            std::condition_variable m_condition;      ///< Condition variable for waiting operations
            std::atomic<size_t> m_count{ 0 };           ///< Atomic counter for fast empty checks
            size_t m_capacity{ 0 };                     ///< Maximum capacity (0 = unlimited)
        };

    } // namespace net2
} // namespace mz

#endif // NET_SAFE_QUEUE_HEADER_FILE
