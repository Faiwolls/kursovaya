// server.cpp - Cross-platform messenger server
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>
#include <atomic>
#include <exception>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <csignal>
#include <sys/select.h>
#define SOCKET_TYPE int
#define CLOSE_SOCKET close
#endif

struct User {
    std::string password;
    std::set<std::string> groups;
    bool online = false;
};

std::unordered_map<std::string, User> users;
std::map<std::string, std::set<std::string>> groups;
std::unordered_map<std::string, SOCKET_TYPE> online_users;
std::mutex users_mutex, groups_mutex, online_mutex;
std::atomic<bool> running{ true };
SOCKET_TYPE server_socket_global;

std::string get_current_time() {
    std::time_t now = std::time(nullptr);
    std::tm* tm = std::localtime(&now);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", tm);
    return std::string(buffer);
}

void send_to_client(SOCKET_TYPE socket, const std::string& message) {
    std::string msg = message + "\n";
    send(socket, msg.c_str(), msg.size(), 0);
}

void broadcast_to_group(const std::string& group_name, const std::string& sender, const std::string& message, bool is_system = false) {
    std::lock_guard<std::mutex> lock_online(online_mutex);
    std::lock_guard<std::mutex> lock_groups(groups_mutex);

    if (groups.find(group_name) == groups.end()) return;

    for (const auto& member : groups[group_name]) {
        if (online_users.find(member) != online_users.end()) {
            std::string full_msg;
            if (is_system) {
                full_msg = "[SYSTEM][" + group_name + "] " + message;
            }
            else {
                full_msg = "[GROUP][" + group_name + "] " + sender + " (" + get_current_time() + "): " + message;
            }
            send_to_client(online_users[member], full_msg);
        }
    }
}

std::string read_socket(SOCKET_TYPE socket) {
    char buffer[1024];
    std::string data;
    while (true) {
        int bytes = recv(socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break;
        buffer[bytes] = '\0';
        data += buffer;
        if (data.find('\n') != std::string::npos) break;
    }
    return data.substr(0, data.find('\n'));
}

void save_data() {
    try {
        std::ofstream users_file("users.txt");
        for (const auto& user_entry : users) {
            const std::string& username = user_entry.first;
            const User& user = user_entry.second;
            users_file << username << ":" << user.password << ":";
            for (const auto& group : user.groups) {
                users_file << group << ",";
            }
            users_file << "\n";
        }

        std::ofstream groups_file("groups.txt");
        for (const auto& group_entry : groups) {
            const std::string& group_name = group_entry.first;
            const std::set<std::string>& members = group_entry.second;
            groups_file << group_name << ":";
            for (const auto& member : members) {
                groups_file << member << ",";
            }
            groups_file << "\n";
        }

        std::cout << "Data saved successfully" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error saving data: " << e.what() << std::endl;
    }
}

void load_data() {
    try {
        std::ifstream users_file("users.txt");
        if (users_file.is_open()) {
            std::string line;
            while (std::getline(users_file, line)) {
                size_t pos1 = line.find(':');
                size_t pos2 = line.find(':', pos1 + 1);
                if (pos1 == std::string::npos || pos2 == std::string::npos) continue;

                std::string username = line.substr(0, pos1);
                std::string password = line.substr(pos1 + 1, pos2 - pos1 - 1);
                std::string groups_str = line.substr(pos2 + 1);

                User user;
                user.password = password;
                user.online = false;

                size_t start = 0;
                size_t end = groups_str.find(',');
                while (end != std::string::npos) {
                    std::string group = groups_str.substr(start, end - start);
                    if (!group.empty()) {
                        user.groups.insert(group);
                    }
                    start = end + 1;
                    end = groups_str.find(',', start);
                }

                users[username] = user;
            }
        }

        std::ifstream groups_file("groups.txt");
        if (groups_file.is_open()) {
            std::string line;
            while (std::getline(groups_file, line)) {
                size_t pos = line.find(':');
                if (pos == std::string::npos) continue;

                std::string group_name = line.substr(0, pos);
                std::string members_str = line.substr(pos + 1);

                std::set<std::string> members;
                size_t start = 0;
                size_t end = members_str.find(',');
                while (end != std::string::npos) {
                    std::string member = members_str.substr(start, end - start);
                    if (!member.empty()) {
                        members.insert(member);
                    }
                    start = end + 1;
                    end = members_str.find(',', start);
                }

                groups[group_name] = members;
            }
        }

        std::cout << "Data loaded successfully" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading data: " << e.what() << std::endl;
    }
}

void handle_client(SOCKET_TYPE client_socket) {
    std::string username;
    try {
        bool authenticated = false;
        while (!authenticated) {
            std::string data = read_socket(client_socket);
            if (data.empty()) break;

            std::istringstream iss(data);
            std::string command, pass;
            iss >> command >> username >> pass;

            {
                std::lock_guard<std::mutex> lock(users_mutex);

                if (command == "/register") {
                    if (users.find(username) != users.end()) {
                        send_to_client(client_socket, "ERROR: User already exists");
                    }
                    else {
                        users[username] = { pass, {}, false };
                        save_data();
                        std::cout << "New user registered: " << username << std::endl;
                        send_to_client(client_socket, "SUCCESS");
                    }
                }
                else if (command == "/login") {
                    if (users.find(username) == users.end() || users[username].password != pass) {
                        send_to_client(client_socket, "ERROR: Invalid credentials");
                    }
                    else if (users[username].online) {
                        send_to_client(client_socket, "ERROR: User already online");
                    }
                    else {
                        users[username].online = true;
                        authenticated = true;

                        std::lock_guard<std::mutex> lock_online(online_mutex);
                        online_users[username] = client_socket;

                        std::string groups_list = "GROUPS:";
                        for (const auto& group : users[username].groups) {
                            groups_list += group + ",";
                        }
                        send_to_client(client_socket, groups_list);
                        std::cout << "User logged in: " << username << std::endl;
                        send_to_client(client_socket, "SUCCESS");
                    }
                }
            }
        }

        while (authenticated) {
            std::string data = read_socket(client_socket);
            if (data.empty()) break;

            std::istringstream iss(data);
            std::string command;
            iss >> command;

            if (command == "/pm") {
                std::string recipient;
                std::string message;
                iss >> recipient;
                std::getline(iss, message);

                std::lock_guard<std::mutex> lock_online(online_mutex);
                if (online_users.find(recipient) != online_users.end()) {
                    std::string full_msg = "[PM] " + username + " (" + get_current_time() + "):" + message;
                    send_to_client(online_users[recipient], full_msg);
                    std::cout << "PM sent from " << username << " to " << recipient << std::endl;
                    send_to_client(client_socket, "SUCCESS");
                }
                else {
                    send_to_client(client_socket, "ERROR: User offline");
                }
            }
            else if (command == "/create_group") {
                std::string group_name;
                iss >> group_name;

                {
                    std::lock_guard<std::mutex> lock(groups_mutex);
                    if (groups.find(group_name) != groups.end()) {
                        send_to_client(client_socket, "ERROR: Group exists");
                    }
                    else {
                        groups[group_name] = { username };

                        std::lock_guard<std::mutex> lock_users(users_mutex);
                        users[username].groups.insert(group_name);

                        save_data();
                        std::cout << "Group created: " << group_name << " (owner: " << username << ")" << std::endl;
                        send_to_client(client_socket, "SUCCESS");
                    }
                }
            }
            else if (command == "/join_group") {
                std::string group_name;
                iss >> group_name;

                {
                    std::lock_guard<std::mutex> lock(groups_mutex);
                    if (groups.find(group_name) == groups.end()) {
                        send_to_client(client_socket, "ERROR: Group not found");
                        continue;
                    }
                    groups[group_name].insert(username);
                }

                {
                    std::lock_guard<std::mutex> lock(users_mutex);
                    users[username].groups.insert(group_name);
                }

                save_data();
                broadcast_to_group(group_name, "SYSTEM", username + " joined group", true);
                std::cout << "User joined group: " << username << " -> " << group_name << std::endl;
                send_to_client(client_socket, "SUCCESS");
            }
            else if (command == "/msg_group") {
                std::string group_name;
                iss >> group_name;
                std::string message;
                std::getline(iss, message);

                {
                    std::lock_guard<std::mutex> lock(groups_mutex);
                    if (groups.find(group_name) == groups.end()) {
                        send_to_client(client_socket, "ERROR: Group not found");
                        continue;
                    }
                    if (groups[group_name].find(username) == groups[group_name].end()) {
                        send_to_client(client_socket, "ERROR: Not in group");
                        continue;
                    }
                }

                broadcast_to_group(group_name, username, message);
                std::cout << "Group message sent to " << group_name << " by " << username << std::endl;
                send_to_client(client_socket, "SUCCESS");
            }
            else if (command == "/users") {
                std::lock_guard<std::mutex> lock(users_mutex);
                std::string response = "USER LIST:\n";
                for (const auto& user : users) {
                    response += user.first + " - " + (user.second.online ? "Online" : "Offline") + "\n";
                }
                send_to_client(client_socket, response);
            }
            else if (command == "/groups") {
                std::lock_guard<std::mutex> lock_groups(groups_mutex);
                std::lock_guard<std::mutex> lock_online(online_mutex);

                std::string response = "GROUP LIST:\n";
                for (const auto& group : groups) {
                    int online_count = 0;
                    for (const auto& member : group.second) {
                        if (online_users.find(member) != online_users.end()) {
                            online_count++;
                        }
                    }
                    response += group.first + " (" + std::to_string(group.second.size()) +
                        " members, online: " + std::to_string(online_count) + ")\n";
                }
                send_to_client(client_socket, response);
            }
            else if (command == "/group_info") {
                std::string group_name;
                iss >> group_name;

                std::lock_guard<std::mutex> lock_groups(groups_mutex);
                std::lock_guard<std::mutex> lock_online(online_mutex);

                if (groups.find(group_name) == groups.end()) {
                    send_to_client(client_socket, "ERROR: Group not found");
                    continue;
                }

                std::string response = "GROUP " + group_name + " MEMBERS:\n";
                for (const auto& member : groups[group_name]) {
                    std::string status = "offline";
                    if (online_users.find(member) != online_users.end()) {
                        status = "online";
                    }
                    response += " - " + member + " [" + status + "]\n";
                }
                send_to_client(client_socket, response);
            }
            else if (command == "/logout") {
                break;
            }
            else {
                send_to_client(client_socket, "ERROR: Unknown command");
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown client error" << std::endl;
    }

    if (!username.empty()) {
        {
            std::lock_guard<std::mutex> lock(users_mutex);
            std::lock_guard<std::mutex> lock_online(online_mutex);

            users[username].online = false;
            online_users.erase(username);
        }
        std::cout << "User logged out: " << username << std::endl;
    }
    CLOSE_SOCKET(client_socket);
}

#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        running = false;
        CLOSE_SOCKET(server_socket_global);
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int signal) {
    running = false;
    CLOSE_SOCKET(server_socket_global);
}
#endif

int main() {
#ifdef _WIN32
    // Use default console encoding
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock init error" << std::endl;
        return 1;
    }
#endif

    std::cout << "Starting messenger server..." << std::endl;
    load_data();

    SOCKET_TYPE server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Socket creation error" << std::endl;
        return 1;
    }
    server_socket_global = server_socket;

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12345);

    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Socket bind error" << std::endl;
        return 1;
    }

    if (listen(server_socket, 10) == -1) {
        std::cerr << "Listen error" << std::endl;
        return 1;
    }

    std::cout << "Server running on port 12345" << std::endl;
    std::cout << "Press Ctrl+C to stop server and save data" << std::endl;

    while (running) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(server_socket, &read_set);

        timeval timeout = { 1, 0 };

        int activity = select(server_socket + 1, &read_set, NULL, NULL, &timeout);

        if (activity < 0 && running) {
            std::cerr << "Select error" << std::endl;
            continue;
        }

        if (activity > 0 && FD_ISSET(server_socket, &read_set)) {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            SOCKET_TYPE client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);

            if (client_socket == -1) {
                if (!running) break;
                std::cerr << "Accept error" << std::endl;
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "New connection: " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;
            std::thread(handle_client, client_socket).detach();
        }
    }

    save_data();
    CLOSE_SOCKET(server_socket);

#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "Server stopped. Data saved." << std::endl;
    return 0;
}