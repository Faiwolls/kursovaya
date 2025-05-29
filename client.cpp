// client.cpp - Кроссплатформенный клиент мессенджера
#include <iostream>
#include <string>
#include <thread>
#include <vector>
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

class MessengerClient {
public:
    MessengerClient(const std::string& host, short port)
        : connected(false) {
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

        socket_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd == -1) {
            std::cerr << "Socket creation failed\n";
            return;
        }

        sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid address\n";
            return;
        }

        if (connect(socket_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            std::cerr << "Connection failed\n";
            return;
        }

        connected = true;
    }

    void start() {
        if (!connected) {
            std::cerr << "Not connected to server\n";
            return;
        }

        std::thread receiver_thread(&MessengerClient::receive_messages, this);
        receiver_thread.detach();

        std::cout << "Messenger Client\n";
        std::cout << "Commands:\n";
        std::cout << "  /register <username> <password>\n";
        std::cout << "  /login <username> <password>\n";
        std::cout << "  /pm <user> <message>\n";
        std::cout << "  /create_group <name>\n";
        std::cout << "  /join_group <name>\n";
        std::cout << "  /msg_group <group> <message>\n";
        std::cout << "  /logout\n\n";

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
                std::cerr << "\nConnection lost\n";
                break;
            }
            buffer[bytes] = '\0';
            std::cout << "\n[New Message] " << buffer << "\n> " << std::flush;
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