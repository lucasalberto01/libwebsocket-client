#ifndef EASYWSCLIENT_HPP_20120819_MIOFVASDTNUASZDQPLFD
#define EASYWSCLIENT_HPP_20120819_MIOFVASDTNUASZDQPLFD

// This code comes from:
// https://github.com/dhbaird/easywsclient
//
// To get the latest version:
// wget https://raw.github.com/dhbaird/easywsclient/master/easywsclient.hpp
// wget https://raw.github.com/dhbaird/easywsclient/master/easywsclient.cpp

#include <functional>
#include <iostream>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

typedef int socket_t;

class Verbose {
  public:
    enum eLevel { VERBOSITY_QUIET = 0, VERBOSITY_NORMAL = 1, VERBOSITY_VERBOSE = 2, VERBOSITY_VERY_VERBOSE = 3, VERBOSITY_DEBUG = 4 };

    eLevel th;

  public:
    std::string ToString(eLevel lev) {
        switch (lev) {
            case VERBOSITY_QUIET:
                return std::string("QUIET");
            case VERBOSITY_NORMAL:
                return std::string("NORMAL");
            case VERBOSITY_VERBOSE:
                return std::string("VERBOSE");
            case VERBOSITY_VERY_VERBOSE:
                return std::string("VERY_VERBOSE");
            case VERBOSITY_DEBUG:
                return std::string("DEBUG");
            default:
                return std::string("UNKNOWN");
        }
    }

    void show(std::string str, eLevel lev) {
        if (lev <= th) {
            std::cout << std::string("[") << ToString(lev) << std::string("]") << std::string(" - ") << str << std::endl;
        }
    }

    void SetTh(eLevel _th) {
        th = _th;
    }
};

struct Callback_Imp {
    virtual void operator()(const std::string &message) = 0;
};
struct BytesCallback_Imp {
    virtual void operator()(const std::vector<uint8_t> &message) = 0;
};
struct wsheader_type {
    unsigned header_size;
    bool fin;
    bool mask;
    enum opcode_type {
        CONTINUATION = 0x0,
        TEXT_FRAME = 0x1,
        BINARY_FRAME = 0x2,
        CLOSE = 8,
        PING = 0x09,
        PONG = 0xa,
    } opcode;
    int N0;
    uint64_t N;
    uint8_t masking_key[4];
};

class WebSocket {
  public:
    // http://tools.ietf.org/html/rfc6455#section-5.2  Base Framing Protocol
    //
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-------+-+-------------+-------------------------------+
    // |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
    // |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
    // |N|V|V|V|       |S|             |   (if payload len==126/127)   |
    // | |1|2|3|       |K|             |                               |
    // +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
    // |     Extended payload length continued, if payload len == 127  |
    // + - - - - - - - - - - - - - - - +-------------------------------+
    // |                               |Masking-key, if MASK set to 1  |
    // +-------------------------------+-------------------------------+
    // | Masking-key (continued)       |          Payload Data         |
    // +-------------------------------- - - - - - - - - - - - - - - - +
    // :                     Payload Data continued ...                :
    // + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
    // |                     Payload Data continued ...                |
    // +---------------------------------------------------------------+
    typedef enum readyStateValues { CLOSING, CLOSED, CONNECTING, OPEN } readyStateValues;

    std::vector<uint8_t> rxbuf;
    std::vector<uint8_t> txbuf;
    std::vector<uint8_t> receivedData;

    socket_t sockfd;
    readyStateValues readyState;
    bool useMask;
    bool isRxBad;

    std::string host;
    std::string extraHeaders;

    // Callbacks functions pointers, initialized to NULL
    std::function<void(const std::vector<u_int8_t> &message)> messageCallback;
    std::function<void()> openCallback;
    std::function<void()> closeCallback;

    // Loop receive thread
    std::thread loopThread;

    Verbose logger;

    // Constructor
    WebSocket();
    ~WebSocket();

    // Public methods
    int from_url(const std::string &url, bool useMask, const std::string &origin);
    readyStateValues getReadyState() const;
    void poll(int timeout = 0);
    void dispatch(std::function<void(const std::string &message)> callable);
    void dispatchBinary(std::function<void(const std::vector<uint8_t> &message)> callable);
    void sendPing();
    void send(const std::string &message);
    void sendBinary(const std::string &message);
    void sendBinary(const std::vector<uint8_t> &message);
    template <class Iterator> void sendData(wsheader_type::opcode_type type, uint64_t message_size, Iterator message_begin, Iterator message_end);
    void close();
    void terminateConnection();
    void begin(bool unblocked = false);
    readyStateValues getReadyState();

    // Setters
    void setExtraHeaders(const std::string extraHeaders);
    void setHost(const std::string host);

    // Callbacks
    void onMessage(std::function<void(const std::vector<u_int8_t> &message)> callback);
    void onConnect(std::function<void()> callback);
    void onClose(std::function<void()> callback);

    // Loops threads
    void loopThreadFunction();

  private:
    // WebSockets do not support being copy constructed or copy assigned.
    // WebSocket(const WebSocket &);
    // WebSocket &operator=(const WebSocket &);
};

#endif /* EASYWSCLIENT_HPP_20120819_MIOFVASDTNUASZDQPLFD */
