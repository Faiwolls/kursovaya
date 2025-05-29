// server.cpp - Кроссплатформенный сервер мессенджера
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

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#define SOCKET_TYPE int
#define CLOSE_SOCKET close
#endif

// Структура для хранения данных пользователя
struct User {
    std::string password;
    std::set<std::string> groups;
    bool online = false;
};

// Глобальные структуры данных
std::unordered_map<std::string, User> users;
std::map<std::string, std::set<std::string>> groups;
std::unordered_map<std::string, SOCKET_TYPE> online_users;
std::mutex users_mutex, groups_mutex, online_mutex;

// Функция для получения текущего времени
std::string get_current_time() {
    std::time_t now = std::time(nullptr);
    std::tm* tm = std::localtime(&now);
    char buffer[20];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", tm);
    return std::string(buffer);
}

// Отправка сообщения клиенту
void send_to_client(SOCKET_TYPE socket, const std::string& message) {
    std::string msg = message + "\n";
    send(socket, msg.c_str(), msg.size(), 0);
}

// Рассылка сообщения всем участникам группы
void broadcast_to_group(const std::string& group_name, const std::string& sender, const std::string& message) {
    std::lock_guard<std::mutex> lock(groups_mutex);
    if (groups.find(group_name) == groups.end()) return;

    std::lock_guard<std::mutex> lock_online(online_mutex);
    for (const auto& member : groups[group_name]) {
        if (member == sender) continue;
        if (online_users.find(member) != online_users.end()) {
            std::string full_msg = "[GROUP:" + group_name + "] " + sender + " (" + get_current_time() + "): " + message;
            send_to_client(online_users[member], full_msg);
        }
    }
}

// Чтение строки из сокета
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

// Обработка клиентской сессии
void handle_client(SOCKET_TYPE client_socket) {
    std::string username;
    try {
        // Этап аутентификации
        bool authenticated = false;
        while (!authenticated) {
            std::string data = read_socket(client_socket);
            std::istringstream iss(data);
            std::string command, pass;
            iss >> command >> username >> pass;

            std::lock_guard<std::mutex> lock(users_mutex);

            if (command == "/register") {
                if (users.find(username) != users.end()) {
                    send_to_client(client_socket, "ERROR: Username already exists");
                }
                else {
                    users[username] = { pass, {}, false };
                    send_to_client(client_socket, "SUCCESS: Registration successful");
                }
            }
            else if (command == "/login") {
                if (users.find(username) == users.end() || users[username].password != pass) {
                    send_to_client(client_socket, "ERROR: Invalid credentials");
                }
                else if (users[username].online) {
                    send_to_client(client_socket, "ERROR: User already logged in");
                }
                else {
                    users[username].online = true;
                    authenticated = true;

                    // Добавляем в онлайн
                    std::lock_guard<std::mutex> lock_online(online_mutex);
                    online_users[username] = client_socket;

                    // Отправляем список групп
                    std::string groups_list = "GROUPS:";
                    for (const auto& group : users[username].groups) {
                        groups_list += group + ",";
                    }
                    send_to_client(client_socket, groups_list);
                    send_to_client(client_socket, "SUCCESS: Login successful");
                }
            }
        }

        // Основной цикл обработки команд
        while (true) {
            std::string data = read_socket(client_socket);
            if (data.empty()) break;

            std::istringstream iss(data);
            std::string command;
            iss >> command;

            if (command == "/pm") {
                std::string recipient, message;
                iss >> recipient;
                std::getline(iss, message);

                std::lock_guard<std::mutex> lock_online(online_mutex);
                if (online_users.find(recipient) != online_users.end()) {
                    std::string full_msg = "[PM] " + username + " (" + get_current_time() + "):" + message;
                    send_to_client(online_users[recipient], full_msg);
                    send_to_client(client_socket, "SUCCESS: Message sent");
                }
                else {
                    send_to_client(client_socket, "ERROR: User not online");
                }
            }
            else if (command == "/create_group") {
                std::string group_name;
                iss >> group_name;

                std::lock_guard<std::mutex> lock(groups_mutex);
                if (groups.find(group_name) != groups.end()) {
                    send_to_client(client_socket, "ERROR: Group already exists");
                }
                else {
                    groups[group_name] = { username };

                    // Добавляем группу пользователю
                    std::lock_guard<std::mutex> lock_users(users_mutex);
                    users[username].groups.insert(group_name);

                    send_to_client(client_socket, "SUCCESS: Group created");
                }
            }
            else if (command == "/join_group") {
                std::string group_name;
                iss >> group_name;

                // Исправление: уменьшаем область действия мьютекса
                {
                    std::lock_guard<std::mutex> lock(groups_mutex);
                    if (groups.find(group_name) == groups.end()) {
                        send_to_client(client_socket, "ERROR: Group doesn't exist");
                        continue;
                    }
                    groups[group_name].insert(username);
                }

                {
                    std::lock_guard<std::mutex> lock(users_mutex);
                    users[username].groups.insert(group_name);
                }

                // Уведомляем группу (без блокировки groups_mutex)
                broadcast_to_group(group_name, "SYSTEM", username + " joined the group");
                send_to_client(client_socket, "SUCCESS: Joined group");
            }
            else if (command == "/msg_group") {
                std::string group_name;
                iss >> group_name;
                std::string message;
                std::getline(iss, message);

                std::lock_guard<std::mutex> lock(groups_mutex);
                if (groups.find(group_name) == groups.end()) {
                    send_to_client(client_socket, "ERROR: Group doesn't exist");
                }
                else if (groups[group_name].find(username) == groups[group_name].end()) {
                    send_to_client(client_socket, "ERROR: Not a member of this group");
                }
                else {
                    broadcast_to_group(group_name, username, message);
                    send_to_client(client_socket, "SUCCESS: Message sent to group");
                }
            }
            else if (command == "/logout") {
                break;
            }
        }
    }
    catch (...) {
        // Ошибка соединения
    }

    // Очистка при выходе
    if (!username.empty()) {
        std::lock_guard<std::mutex> lock(users_mutex);
        std::lock_guard<std::mutex> lock_online(online_mutex);

        users[username].online = false;
        online_users.erase(username);
    }
    CLOSE_SOCKET(client_socket);
}

int main() {
    // Инициализация сокетов для Windows
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    // Создание сокета
    SOCKET_TYPE server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }

    // Настройка адреса сервера
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(12345);

    // Привязка сокета
    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Bind failed\n";
        return 1;
    }

    // Прослушивание порта
    if (listen(server_socket, 10) == -1) {
        std::cerr << "Listen failed\n";
        return 1;
    }

    std::cout << "Server started on port 12345\n";

    // Основной цикл сервера
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        SOCKET_TYPE client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_len);

        if (client_socket == -1) {
            std::cerr << "Accept failed\n";
            continue;
        }

        std::thread(handle_client, client_socket).detach();
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}