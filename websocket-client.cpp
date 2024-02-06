
#ifdef _WIN32
    #if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
        #define _CRT_SECURE_NO_WARNINGS // _CRT_SECURE_NO_WARNINGS for sscanf errors in MSVC2013 Express
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <WS2tcpip.h>
    #include <WinSock2.h>
    #include <fcntl.h>
    #pragma comment(lib, "ws2_32")
    #include <sys/types.h>
    #include <io.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #ifndef _SSIZE_T_DEFINED
typedef int ssize_t;
        #define _SSIZE_T_DEFINED
    #endif
    #ifndef _SOCKET_T_DEFINED
typedef SOCKET socket_t;
        #define _SOCKET_T_DEFINED
    #endif
    #ifndef snprintf
        #define snprintf _snprintf_s
    #endif
    #if _MSC_VER >= 1600
        // vs2010 or later
        #include <stdint.h>
    #else
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
    #endif
    #define socketerrno WSAGetLastError()
    #define SOCKET_EAGAIN_EINPROGRESS WSAEINPROGRESS
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
#else
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/socket.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #ifndef _SOCKET_T_DEFINED
typedef int socket_t;
        #define _SOCKET_T_DEFINED
    #endif
    #ifndef INVALID_SOCKET
        #define INVALID_SOCKET (-1)
    #endif
    #ifndef SOCKET_ERROR
        #define SOCKET_ERROR (-1)
    #endif
    #define closesocket(s) ::close(s)
    #include <errno.h>
    #define socketerrno errno
    #define SOCKET_EAGAIN_EINPROGRESS EAGAIN
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
#endif

#include "websocket-client.hpp"
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define GLOBAL ::

socket_t hostname_connect(const std::string &hostname, int port) {
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *p;
    int ret;
    socket_t sockfd = INVALID_SOCKET;
    char sport[16];
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(sport, 16, "%d", port);

    if ((ret = getaddrinfo(hostname.c_str(), sport, &hints, &result)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    for (p = result; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == INVALID_SOCKET) {
            continue;
        }
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) != SOCKET_ERROR) {
            break;
        }
        closesocket(sockfd);
        sockfd = INVALID_SOCKET;
    }
    freeaddrinfo(result);
    return sockfd;
}

WebSocket::~WebSocket() {
    // If the socket has not been closed by the time the destructor is run
    // then we ensure it is closed. This might cause an unclean close as
    // described in RFC 6455, but this is better than leaking file descriptors.
    terminateConnection();
}

WebSocket::WebSocket() {
    this->sockfd = INVALID_SOCKET;
    this->readyState = CONNECTING;
    this->isRxBad = false;
    this->useMask = true;
    this->openCallback = NULL;
    this->messageCallback = NULL;
    this->closeCallback = NULL;
    logger.SetTh(logger.VERBOSITY_NORMAL);
}

WebSocket::readyStateValues WebSocket::getReadyState() const {
    return this->readyState;
}

void WebSocket::begin(bool unblocked) {

    // check host exist
    if (this->host.empty()) {
        logger.show("Error: Host is empty", Verbose::VERBOSITY_NORMAL);
        logger.show("Please set the host using setHost method\n", Verbose::VERBOSITY_NORMAL);
        exit(1);
        return;
    }

    // Start loop thread
    this->loopThread = std::thread(&WebSocket::loopThreadFunction, this);

    if (unblocked && this->loopThread.joinable()) {
        this->loopThread.join();
    }
}

template <class Iterator> // Iterator's value_type must be uint8_t
void WebSocket::sendData(wsheader_type::opcode_type type, uint64_t message_size, Iterator message_begin, Iterator message_end) {
    // TODO:
    // Masking key should (must) be derived from a high quality random
    // number generator, to mitigate attacks on non-WebSocket friendly
    // middleware:
    const uint8_t masking_key[4] = {0x12, 0x34, 0x56, 0x78};

    // TODO: consider acquiring a lock on txbuf...
    if (readyState == CLOSING || readyState == CLOSED) {
        return;
    }

    std::vector<uint8_t> header;
    header.assign(2 + (message_size >= 126 ? 2 : 0) + (message_size >= 65536 ? 6 : 0) + (this->useMask ? 4 : 0), 0);
    header[0] = 0x80 | type;

    if (false) {
    } else if (message_size < 126) {
        header[1] = (message_size & 0xff) | (this->useMask ? 0x80 : 0);
        if (this->useMask) {
            header[2] = masking_key[0];
            header[3] = masking_key[1];
            header[4] = masking_key[2];
            header[5] = masking_key[3];
        }
    } else if (message_size < 65536) {
        header[1] = 126 | (this->useMask ? 0x80 : 0);
        header[2] = (message_size >> 8) & 0xff;
        header[3] = (message_size >> 0) & 0xff;
        if (this->useMask) {
            header[4] = masking_key[0];
            header[5] = masking_key[1];
            header[6] = masking_key[2];
            header[7] = masking_key[3];
        }
    } else { // TODO: run coverage testing here
        header[1] = 127 | (this->useMask ? 0x80 : 0);
        header[2] = (message_size >> 56) & 0xff;
        header[3] = (message_size >> 48) & 0xff;
        header[4] = (message_size >> 40) & 0xff;
        header[5] = (message_size >> 32) & 0xff;
        header[6] = (message_size >> 24) & 0xff;
        header[7] = (message_size >> 16) & 0xff;
        header[8] = (message_size >> 8) & 0xff;
        header[9] = (message_size >> 0) & 0xff;
        if (this->useMask) {
            header[10] = masking_key[0];
            header[11] = masking_key[1];
            header[12] = masking_key[2];
            header[13] = masking_key[3];
        }
    }
    // N.B. - txbuf will keep growing until it can be transmitted over the
    // socket:
    this->txbuf.insert(this->txbuf.end(), header.begin(), header.end());
    this->txbuf.insert(this->txbuf.end(), message_begin, message_end);
    if (this->useMask) {
        size_t message_offset = this->txbuf.size() - message_size;
        for (size_t i = 0; i != message_size; ++i) {
            this->txbuf[message_offset + i] ^= masking_key[i & 0x3];
        }
    }
}

void WebSocket::sendBinary(const std::string &message) {
    this->sendData(wsheader_type::BINARY_FRAME, message.size(), message.begin(), message.end());
}

void WebSocket::sendBinary(const std::vector<uint8_t> &message) {
    this->sendData(wsheader_type::BINARY_FRAME, message.size(), message.begin(), message.end());
}

void WebSocket::send(const std::string &message) {
    this->sendData(wsheader_type::TEXT_FRAME, message.size(), message.begin(), message.end());
}

void WebSocket::sendPing() {
    logger.show("PING SEND!\n", Verbose::VERBOSITY_NORMAL);
    std::string empty;
    this->sendData(wsheader_type::PING, empty.size(), empty.begin(), empty.end());
}

void WebSocket::dispatch(std::function<void(const std::string &message)> callable) {
    return this->dispatchBinary([callable](const std::vector<uint8_t> &message) {
        // TODO: consider acquiring a lock on rxbuf...
        callable(std::string(message.begin(), message.end()));
    });
}

void WebSocket::dispatchBinary(std::function<void(const std::vector<uint8_t> &message)> callable) {
    // TODO: consider acquiring a lock on rxbuf...
    if (this->isRxBad) {
        return;
    }
    while (true) {
        wsheader_type ws;

        if (this->rxbuf.size() < 2) {
            return; /* Need at least 2 */
        }

        const uint8_t *data = (uint8_t *)&this->rxbuf[0]; // peek, but don't consume

        ws.fin = (data[0] & 0x80) == 0x80;
        ws.opcode = (wsheader_type::opcode_type)(data[0] & 0x0f);
        ws.mask = (data[1] & 0x80) == 0x80;
        ws.N0 = (data[1] & 0x7f);
        ws.header_size = 2 + (ws.N0 == 126 ? 2 : 0) + (ws.N0 == 127 ? 8 : 0) + (ws.mask ? 4 : 0);

        if (this->rxbuf.size() < ws.header_size) {
            return; /* Need: ws.header_size - rxbuf.size() */
        }

        int i = 0;
        if (ws.N0 < 126) {
            ws.N = ws.N0;
            i = 2;
        } else if (ws.N0 == 126) {
            ws.N = 0;
            ws.N |= ((uint64_t)data[2]) << 8;
            ws.N |= ((uint64_t)data[3]) << 0;
            i = 4;
        } else if (ws.N0 == 127) {
            ws.N = 0;
            ws.N |= ((uint64_t)data[2]) << 56;
            ws.N |= ((uint64_t)data[3]) << 48;
            ws.N |= ((uint64_t)data[4]) << 40;
            ws.N |= ((uint64_t)data[5]) << 32;
            ws.N |= ((uint64_t)data[6]) << 24;
            ws.N |= ((uint64_t)data[7]) << 16;
            ws.N |= ((uint64_t)data[8]) << 8;
            ws.N |= ((uint64_t)data[9]) << 0;
            i = 10;
            if (ws.N & 0x8000000000000000ull) {
                // https://tools.ietf.org/html/rfc6455 writes the "the most
                // significant bit MUST be 0."
                //
                // We can't drop the frame, because (1) we don't we don't
                // know how much data to skip over to find the next header,
                // and (2) this would be an impractically long length, even
                // if it were valid. So just close() and return immediately
                // for now.
                this->isRxBad = true;
                logger.show("ERROR: Frame has invalid frame length. Closing.\n", Verbose::VERBOSITY_NORMAL);
                this->close();
                return;
            }
        }
        if (ws.mask) {
            ws.masking_key[0] = ((uint8_t)data[i + 0]) << 0;
            ws.masking_key[1] = ((uint8_t)data[i + 1]) << 0;
            ws.masking_key[2] = ((uint8_t)data[i + 2]) << 0;
            ws.masking_key[3] = ((uint8_t)data[i + 3]) << 0;
        } else {
            ws.masking_key[0] = 0;
            ws.masking_key[1] = 0;
            ws.masking_key[2] = 0;
            ws.masking_key[3] = 0;
        }

        // Note: The checks above should hopefully ensure this addition
        //       cannot overflow:
        if (this->rxbuf.size() < ws.header_size + ws.N) {
            return; /* Need: ws.header_size+ws.N - rxbuf.size() */
        }

        // We got a whole message, now do something with it:
        if (false) {
        } else if (ws.opcode == wsheader_type::TEXT_FRAME || ws.opcode == wsheader_type::BINARY_FRAME || ws.opcode == wsheader_type::CONTINUATION) {
            if (ws.mask) {
                for (size_t i = 0; i != ws.N; ++i) {
                    this->rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3];
                }
            }
            this->receivedData.insert(this->receivedData.end(), this->rxbuf.begin() + ws.header_size, this->rxbuf.begin() + ws.header_size + (size_t)ws.N); // just feed

            if (ws.fin) {
                callable((const std::vector<uint8_t>)this->receivedData);

                this->receivedData.erase(this->receivedData.begin(), this->receivedData.end());
                std::vector<uint8_t>().swap(this->receivedData); // free memory
            }
        } else if (ws.opcode == wsheader_type::PING) {
            logger.show("PING!\n", Verbose::VERBOSITY_NORMAL);
            if (ws.mask) {
                for (size_t i = 0; i != ws.N; ++i) {
                    this->rxbuf[i + ws.header_size] ^= ws.masking_key[i & 0x3];
                }
            }
            std::string data(this->rxbuf.begin() + ws.header_size, this->rxbuf.begin() + ws.header_size + (size_t)ws.N);
            this->sendData(wsheader_type::PING, data.size(), data.begin(), data.end());

        } else if (ws.opcode == wsheader_type::PONG) {
            logger.show("PONG!\n", Verbose::VERBOSITY_NORMAL);
        } else if (ws.opcode == wsheader_type::CLOSE) {
            close();
        } else {
            logger.show("ERROR: Got unexpected WebSocket message.\n", Verbose::VERBOSITY_NORMAL);
            close();
        }

        this->rxbuf.erase(this->rxbuf.begin(), this->rxbuf.begin() + ws.header_size + (size_t)ws.N);
    }
}

void WebSocket::loopThreadFunction() {
    while (true) {

        readyStateValues state = this->getReadyState();

        if (state == WebSocket::CONNECTING) {
            int success = this->from_url(this->host, true, "");
            if (success == -1) {
                // Await 5 second before trying to reconnect
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        } else if (state == WebSocket::OPEN) {
            this->poll();

            this->dispatchBinary([this](const std::vector<uint8_t> &message) {
                logger.show("Received message of length " + std::to_string(message.size()) + "\n", Verbose::VERBOSITY_NORMAL);
                if (this->messageCallback) {
                    this->messageCallback(message);
                }
            });

        } else if (state == WebSocket::CLOSING) {
            logger.show("WebSocket is closing...\n", Verbose::VERBOSITY_NORMAL);
        } else if (state == WebSocket::CLOSED) {
            logger.show("WebSocket is closed! Retry\n", Verbose::VERBOSITY_NORMAL);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            // Change state to connecting
            this->readyState = WebSocket::CONNECTING;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void WebSocket::poll(int timeout) { // timeout in milliseconds
    if (this->readyState == CLOSED) {
        if (timeout > 0) {
            timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
            GLOBAL select(0, NULL, NULL, NULL, &tv);
        }
        return;
    }

    if (timeout != 0) {
        fd_set rfds;
        fd_set wfds;
        timeval tv = {timeout / 1000, (timeout % 1000) * 1000};
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(this->sockfd, &rfds);
        if (this->txbuf.size()) {
            FD_SET(this->sockfd, &wfds);
        }
        GLOBAL select(this->sockfd + 1, &rfds, &wfds, 0, timeout > 0 ? &tv : 0);
    }

    while (true) {
        // FD_ISSET(0, &rfds) will be true
        int N = this->rxbuf.size();
        ssize_t ret;
        this->rxbuf.resize(N + 1500);
        ret = recv(this->sockfd, (char *)&this->rxbuf[0] + N, 1500, 0);
        if (false) {
        } else if (ret < 0 && (socketerrno == SOCKET_EWOULDBLOCK || socketerrno == SOCKET_EAGAIN_EINPROGRESS)) {
            this->rxbuf.resize(N);
            break;
        } else if (ret <= 0) {
            this->rxbuf.resize(N);
            this->terminateConnection();
            logger.show("ERROR:" + std::string(ret < 0 ? "Connection error!" : "Connection closed!") + "\n", Verbose::VERBOSITY_NORMAL);
            break;
        } else {
            this->rxbuf.resize(N + ret);
        }
    }

    while (this->txbuf.size()) {
        int ret = ::send(this->sockfd, (char *)&this->txbuf[0], this->txbuf.size(), 0);

        if (false) {
        } else if (ret < 0 && (socketerrno == SOCKET_EWOULDBLOCK || socketerrno == SOCKET_EAGAIN_EINPROGRESS)) {
            break;
        } else if (ret <= 0) {
            this->terminateConnection();
            logger.show("ERROR:" + std::string(ret < 0 ? "Connection error!" : "Connection closed!") + "\n", Verbose::VERBOSITY_NORMAL);
            logger.show("ret: " + std::to_string(ret) + "\n", Verbose::VERBOSITY_NORMAL);
            break;
        } else {
            this->txbuf.erase(this->txbuf.begin(), this->txbuf.begin() + ret);
        }
    }

    if (!this->txbuf.size() && this->readyState == CLOSING) {
        logger.show("Closing connection\n", Verbose::VERBOSITY_NORMAL);
        logger.show("txbuf.size() == 0\n", Verbose::VERBOSITY_NORMAL);
        this->terminateConnection();
    }
}

void WebSocket::close() {
    if (this->readyState == CLOSING || this->readyState == CLOSED) {
        return;
    }
    this->readyState = CLOSING;
    uint8_t closeFrame[6] = {0x88, 0x80, 0x00, 0x00, 0x00, 0x00}; // last 4 bytes are a masking key
    std::vector<uint8_t> header(closeFrame, closeFrame + 6);
    this->txbuf.insert(this->txbuf.end(), header.begin(), header.end());
}

// Immediately terminates the connection to the remote host, if connected.
//
// This ensures resources and open socket file descriptors are cleaned up.
// Typically this is called once the server closes the underlying socket
// connection, however, it can also be used by the client to force an
// unclean close of the connection.
//
// This method does not throw and it is safe to call multiple times.
void WebSocket::terminateConnection() {

    if (this->sockfd != INVALID_SOCKET) {
        closesocket(this->sockfd);
        this->sockfd = INVALID_SOCKET;
        this->readyState = CLOSED;
    }

    if (this->closeCallback) {
        this->closeCallback();
    }
}

void WebSocket::setHost(const std::string host) {
    this->host = host;
}

void WebSocket::setExtraHeaders(const std::string extraHeaders) {
    this->extraHeaders = extraHeaders;
}

void WebSocket::onMessage(std::function<void(const std::vector<u_int8_t> &message)> callback) {
    this->messageCallback = callback;
}

void WebSocket::onConnect(std::function<void()> callback) {
    this->openCallback = callback;
}

void WebSocket::onClose(std::function<void()> callback) {
    this->closeCallback = callback;
}

// TODO: Retornar -1 em caso de erro, pode ser util na reconexão
int WebSocket::from_url(const std::string &url, bool useMask, const std::string &origin) {
    char host[512];
    int port;
    char path[512];

    if (url.size() >= 512) {
        logger.show("ERROR: url size limit exceeded: " + url + "\n", Verbose::VERBOSITY_NORMAL);
        exit(1);
        return -1;
    }

    if (origin.size() >= 200) {
        logger.show("ERROR: origin size limit exceeded: " + origin + "\n", Verbose::VERBOSITY_NORMAL);
        exit(1);
        return -1;
    }

    if (false) {
    } else if (sscanf(url.c_str(), "ws://%[^:/]:%d/%s", host, &port, path) == 3) {
    } else if (sscanf(url.c_str(), "ws://%[^:/]/%s", host, path) == 2) {
        port = 80;
    } else if (sscanf(url.c_str(), "ws://%[^:/]:%d", host, &port) == 2) {
        path[0] = '\0';
    } else if (sscanf(url.c_str(), "ws://%[^:/]", host) == 1) {
        port = 80;
        path[0] = '\0';
    } else {
        logger.show("ERROR: Could not parse WebSocket url: " + url + "\n", Verbose::VERBOSITY_NORMAL);
        exit(1);
        return -1;
    }
    // fprintf(stderr, "easywsclient: connecting: host=%s port=%d path=/%s\n", host, port, path);
    socket_t sockfd = hostname_connect(host, port);

    if (sockfd == INVALID_SOCKET) {
        logger.show("ERROR: Unable to connect to " + std::string(host) + ":" + std::to_string(port) + "\n", Verbose::VERBOSITY_NORMAL);
        return -1;
    }

    // XXX: this should be done non-blocking,
    char line[1024];
    int status;
    int i;
    GLOBAL snprintf(line, 1024, "GET /%s HTTP/1.1\r\n", path);
    GLOBAL send(sockfd, line, strlen(line), 0);
    if (port == 80) {
        GLOBAL snprintf(line, 1024, "Host: %s\r\n", host);
        GLOBAL send(sockfd, line, strlen(line), 0);
    } else {
        GLOBAL snprintf(line, 1024, "Host: %s:%d\r\n", host, port);
        GLOBAL send(sockfd, line, strlen(line), 0);
    }
    GLOBAL snprintf(line, 1024, "Upgrade: websocket\r\n");
    GLOBAL send(sockfd, line, strlen(line), 0);
    GLOBAL snprintf(line, 1024, "Connection: Upgrade\r\n");
    GLOBAL send(sockfd, line, strlen(line), 0);
    if (!origin.empty()) {
        GLOBAL snprintf(line, 1024, "Origin: %s\r\n", origin.c_str());
        GLOBAL send(sockfd, line, strlen(line), 0);
    }
    GLOBAL snprintf(line, 1024, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n");
    GLOBAL send(sockfd, line, strlen(line), 0);

    // Extra headers
    if (!this->extraHeaders.empty()) {
        GLOBAL snprintf(line, 1024, "%s\r\n", this->extraHeaders.c_str());
        GLOBAL send(sockfd, this->extraHeaders.c_str(), this->extraHeaders.size(), 0);
    }

    GLOBAL snprintf(line, 1024, "Sec-WebSocket-Version: 13\r\n");
    GLOBAL send(sockfd, line, strlen(line), 0);
    GLOBAL snprintf(line, 1024, "\r\n");
    GLOBAL send(sockfd, line, strlen(line), 0);

    for (i = 0; i < 2 || (i < 1023 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
        if (recv(sockfd, line + i, 1, 0) == 0) {
            logger.show("ERROR: Connection closed unexpectedly\n", Verbose::VERBOSITY_NORMAL);
            return -1;
        }
    }
    line[i] = 0;
    if (i == 1023) {
        logger.show("ERROR: Got invalid status line connecting to: " + url + "\n", Verbose::VERBOSITY_NORMAL);
        return -1;
    }
    if (sscanf(line, "HTTP/1.1 %d", &status) != 1 || status != 101) {
        logger.show("ERROR: Got bad status connecting to: " + url + ": " + line + "\n", Verbose::VERBOSITY_NORMAL);
        return -1;
    }
    // TODO: verify response headers,
    while (true) {
        for (i = 0; i < 2 || (i < 1023 && line[i - 2] != '\r' && line[i - 1] != '\n'); ++i) {
            if (recv(sockfd, line + i, 1, 0) == 0) {
                logger.show("ERROR: Connection closed unexpectedly\n", Verbose::VERBOSITY_NORMAL);
                return -1;
            }
        }
        if (line[0] == '\r' && line[1] == '\n') {
            break;
        }
    }

    int flag = 1;
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag)); // Disable Nagle's algorithm

    printf("Connected to: %s\n", url.c_str());

    this->sockfd = sockfd;

    // Call onConnect callback
    if (this->openCallback) {
        this->openCallback();
    }

    this->readyState = OPEN;

#ifdef _WIN32
    u_long on = 1;
    ioctlsocket(sockfd, FIONBIO, &on);
#else
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
#endif
    // fprintf(stderr, "Connected to: %s\n", url.c_str());
    return 0;
}

WebSocket::readyStateValues WebSocket::getReadyState() {
    return this->readyState;
}