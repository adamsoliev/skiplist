#pragma once

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace minilsm
{

class Logger
{
public:
        Logger() = default;

        explicit Logger(const std::string &program_name, const std::string &log_dir = "logs")
        {
                init(program_name, log_dir);
        }

        ~Logger()
        {
                if (log_file_.is_open())
                {
                        log_file_.close();
                }
        }

        Logger(const Logger &) = delete;
        Logger &operator=(const Logger &) = delete;

        bool init(const std::string &program_name, const std::string &log_dir = "logs")
        {
                std::filesystem::create_directories(log_dir);

                auto now = std::chrono::system_clock::now();
                auto time_t_now = std::chrono::system_clock::to_time_t(now);
                std::tm tm_now{};
                localtime_r(&time_t_now, &tm_now);

                std::ostringstream filename;
                filename << log_dir << "/" << program_name << "-log-" << std::put_time(&tm_now, "%Y%m%d-%H%M%S")
                         << ".log";

                log_file_.open(filename.str(), std::ios::out | std::ios::app);
                if (!log_file_.is_open())
                {
                        std::cerr << "Failed to open log file: " << filename.str() << "\n";
                        return false;
                }

                log_path_ = filename.str();
                initialized_ = true;
                return true;
        }

        template <typename... Args>
        void operator()(Args &&...args)
        {
                write("INFO", std::forward<Args>(args)...);
        }

        template <typename... Args>
        void info(Args &&...args)
        {
                write("INFO", std::forward<Args>(args)...);
        }

        template <typename... Args>
        void warn(Args &&...args)
        {
                write("WARN", std::forward<Args>(args)...);
        }

        template <typename... Args>
        void error(Args &&...args)
        {
                write("ERROR", std::forward<Args>(args)...);
        }

        const std::string &log_path() const { return log_path_; }

private:
        template <typename... Args>
        void write(const char *level, Args &&...args)
        {
                std::ostringstream oss;
                ((oss << std::forward<Args>(args)), ...);

                std::string timestamp = get_timestamp();
                std::string line = timestamp + " [" + level + "] " + oss.str();

                std::lock_guard<std::mutex> lock(mutex_);
                std::cout << line << "\n";
                if (initialized_)
                {
                        log_file_ << line << "\n";
                        log_file_.flush();
                }
        }

        std::string get_timestamp()
        {
                auto now = std::chrono::system_clock::now();
                auto time_t_now = std::chrono::system_clock::to_time_t(now);
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

                std::tm tm_now{};
                localtime_r(&time_t_now, &tm_now);

                std::ostringstream oss;
                oss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S") << "." << std::setfill('0') << std::setw(3)
                    << ms.count();
                return oss.str();
        }

        std::mutex mutex_;
        std::ofstream log_file_;
        std::string log_path_;
        bool initialized_ = false;
};

}  // namespace minilsm
