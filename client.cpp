// client.cpp - Cross-platform messenger client
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <string>
#include <thread>
#include <cstring>
#include <Windows.h>

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

class MessengerClient {
public:
    MessengerClient(const std::string& host, short port)
        : connected(false) {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "Winsock init error" << std::endl;
            return;
        }
#endif

        socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd == -1) {
            std::cerr << "Socket creation error" << std::endl;
            return;
        }

        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
            CLOSE_SOCKET(socket_fd);
            std::cerr << "Invalid server address" << std::endl;
            return;
        }

        if (connect(socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            CLOSE_SOCKET(socket_fd);
            std::cerr << "Connection error" << std::endl;
            return;
        }

        connected = true;
    }

    void start() {
        if (!connected) {
            std::cerr << "Not connected to server" << std::endl;
            return;
        }

        std::thread receiver_thread(&MessengerClient::receive_messages, this);
        receiver_thread.detach();

        std::cout << "Messenger Client" << std::endl;
        std::cout << "Available commands:" << std::endl;
        std::cout << "  /register <login> <password> - Register" << std::endl;
        std::cout << "  /login <login> <password>    - Login" << std::endl;
        std::cout << "  /pm <user> <message>         - Private message" << std::endl;
        std::cout << "  /create_group <name>         - Create group" << std::endl;
        std::cout << "  /join_group <name>           - Join group" << std::endl;
        std::cout << "  /msg_group <group> <message> - Group message" << std::endl;
        std::cout << "  /users                       - List users" << std::endl;
        std::cout << "  /groups                      - List groups" << std::endl;
        std::cout << "  /group_info <group>          - Show group members" << std::endl;
        std::cout << "  /logout                      - Logout" << std::endl;
        std::cout << std::endl;

        run();
    }

private:
    void run() {
        while (true) {
            std::string input;
            std::cout << "> ";
            std::getline(std::cin, input);

            if (input.empty()) continue;

            if (input == "/logout") {
                send_message(input);
                break;
            }

            send_message(input);
        }
        CLOSE_SOCKET(socket_fd);
#ifdef _WIN32
        WSACleanup();
#endif
    }

    void send_message(const std::string& message) {
        std::string msg = message + "\n";
        send(socket_fd, msg.c_str(), msg.size(), 0);
    }

    void receive_messages() {
        char buffer[1024];
        while (true) {
            int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                std::cout << "\nConnection lost" << std::endl;
                break;
            }
            buffer[bytes] = '\0';

            // Пропускаем сообщения SUCCESS
            if (std::string(buffer).find("SUCCESS") != 0) {
                std::cout << buffer << std::endl;
            }
            std::cout << "> " << std::flush;
        }
    }

    SOCKET_TYPE socket_fd;
    bool connected;
};

int main() {
    MessengerClient client("127.0.0.1", 12345);
    client.start();
    return 0;
}