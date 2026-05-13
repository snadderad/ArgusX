#pragma once
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads) : m_stop(false) {
        for (size_t i = 0; i < num_threads; i++) {
            m_workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait(lock, [this] {
                            return m_stop || !m_tasks.empty();
                            });
                        if (m_stop && m_tasks.empty()) return;
                        task = std::move(m_tasks.front());
                        m_tasks.pop();
                    }
                    task();
                    m_pending--;
                    m_done_cv.notify_all();
                }
                });
        }
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_stop = true;
        }
        m_cv.notify_all();
        for (auto& w : m_workers) w.join();
    }

    void enqueue(std::function<void()> task) {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_tasks.push(std::move(task));
            m_pending++;
        }
        m_cv.notify_one();
    }

    void wait_all() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_done_cv.wait(lock, [this] { return m_pending == 0; });
    }

private:
    std::vector<std::thread>          m_workers;
    std::queue<std::function<void()>> m_tasks;
    std::mutex                        m_mutex;
    std::condition_variable           m_cv;
    std::condition_variable           m_done_cv;
    std::atomic<int>                  m_pending{ 0 };
    bool                              m_stop;
};