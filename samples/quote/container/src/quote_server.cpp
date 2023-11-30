#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <memory>
#include <tuple>
#include <iostream>
#include "acon_client.h"

using namespace std;

typedef struct
{
    int32_t rtmr_log_offset;
    int32_t attestation_json_offset;
    int32_t data_offset;
    uint8_t data[0];
} quote_header;

class AconSocket
{
public:
    AconSocket() : socket_fd(-1)
    {
        ;
    }

    ~AconSocket()
    {
        if (this->socket_fd > 0)
        {
            close(this->socket_fd);
        }
    }

    size_t send_msg(void *msg_buf, size_t buf_size)
    {
        if (!msg_buf || buf_size == 0)
        {
            return -1;
        }

        if (this->socket_fd < 0 && this->connect() < 0)
        {
            return -1;
        }

        return write(this->socket_fd, msg_buf, buf_size);
    }

    unique_ptr<uint8_t[]> recv_msg()
    {
        if (this->socket_fd < 0 && this->connect() < 0)
        {
            return NULL;
        }

        size_t msg_hdr_size = sizeof(acon_message_hdr_t);
        acon_message_hdr_t msg_hdr = {0};

        if (read(this->socket_fd, &msg_hdr, msg_hdr_size) < msg_hdr_size)
        {
            cerr << "Err: can't read from server." << endl;
            return NULL;
        }

        if (msg_hdr.size < msg_hdr_size)
        {
            cerr << "Err: invalid response format." << endl;
            return NULL;
        }

        unique_ptr<uint8_t[]> msg_buf(new uint8_t[msg_hdr.size + 1]);
        memcpy(msg_buf.get(), &msg_hdr, msg_hdr_size);
        msg_buf[msg_hdr.size] = '\0';

        if (read(this->socket_fd, msg_buf.get() + msg_hdr_size, msg_hdr.size - msg_hdr_size) < 0)
        {
            cerr << "Err: can't read from server." << endl;
            return NULL;
        }

        if (msg_hdr.command < 0)
        {
            cerr << "Err: " << msg_buf.get() + sizeof(acon_message_err_t) << ".(acond)" << endl;
            return NULL;
        }

        return msg_buf;
    }

private:
    int connect()
    {
        int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd == -1)
        {
            cerr << "Err: can't create a socket." << endl;
            return -1;
        }

        struct sockaddr_un client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sun_family = AF_UNIX;
        strncpy(client_addr.sun_path, SOCKET_PATH, sizeof(client_addr.sun_path) - 1);

        if (::connect(socket_fd, (struct sockaddr *)&client_addr, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(SOCKET_PATH)) < 0)
        {
            cerr << "Err: can't connect to acond server." << endl;
            return -1;
        }

        this->socket_fd = socket_fd;
        return this->socket_fd;
    }

private:
    int socket_fd;
};

unique_ptr<uint8_t[]> get_quote(size_t *size)
{
    const char *attest_data = "ATTEST DATA";

    size_t send_buf_hdr_size = sizeof(acon_get_report_req_t);
    size_t send_buf_body_size = strlen(attest_data);
    size_t send_buf_size = send_buf_hdr_size + send_buf_body_size;
    unique_ptr<uint8_t[]> send_buf(new uint8_t[send_buf_size]);

    acon_get_report_req_t get_report_req = {0};
    get_report_req.header.command = 0;
    get_report_req.header.size = send_buf_size;
    get_report_req.data_type = 1;
    get_report_req.nonce[0] = ((uint64_t)rand() << 32) | rand();
    get_report_req.nonce[1] = ((uint64_t)rand() << 32) | rand();
    get_report_req.attest_data_type = 2;

    memcpy(send_buf.get(), &get_report_req, send_buf_hdr_size);
    memcpy(send_buf.get() + send_buf_hdr_size, attest_data, send_buf_body_size);

    AconSocket socket;
    if (socket.send_msg(send_buf.get(), send_buf_size) < 0)
    {
        cerr << "Err: can't send request to server." << endl;
        return NULL;
    }

    unique_ptr<uint8_t[]> recv_buf = socket.recv_msg();
    if (recv_buf == NULL)
    {
        return NULL;
    }

    acon_get_report_rsp_t *get_report_rsp = (acon_get_report_rsp_t *)recv_buf.get();
    if (get_report_rsp->rtmr_log_offset > get_report_rsp->attestation_json_offset
        || get_report_rsp->attestation_json_offset > get_report_rsp->data_offset
        || get_report_rsp->data_offset > get_report_rsp->header.size)
    {
        cerr << "Err: invalid response format." << endl;
        return NULL;
    }

    unique_ptr<uint8_t[]> buf(new uint8_t[sizeof(quote_header) + get_report_rsp->header.size - sizeof(acon_get_report_rsp_t)]);

    quote_header *quote = (quote_header *)buf.get();
    quote->rtmr_log_offset = sizeof(quote_header);
    quote->attestation_json_offset = quote->rtmr_log_offset + get_report_rsp->attestation_json_offset - get_report_rsp->rtmr_log_offset;
    quote->data_offset = quote->attestation_json_offset + get_report_rsp->data_offset - get_report_rsp->attestation_json_offset;
    memcpy(quote->data, recv_buf.get() + get_report_rsp->rtmr_log_offset, get_report_rsp->header.size - sizeof(acon_get_report_rsp_t));

    *size = sizeof(quote_header) + get_report_rsp->header.size - sizeof(acon_get_report_rsp_t);
    return buf;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8085);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        cerr << "Err: can't create socket." << endl;
        exit(EXIT_FAILURE);
    }

    if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        cerr << "Err: can't bind a name to socket." << endl;
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        if (listen(server_fd, 1) < 0)
        {
            cerr << "Err: can't listen for connections on a socket." << endl;
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in sock_addr;
        socklen_t sock_addr_size = sizeof(sock_addr);
        int sock_fd = accept(server_fd, (sockaddr *)&sock_addr, &sock_addr_size);
        if (sock_fd < 0)
        {
            cerr << "Err: can't accept a connection on a socket." << endl;
            exit(EXIT_FAILURE);
        }

        size_t data_size;
        unique_ptr<uint8_t[]> data = get_quote(&data_size);
        ssize_t ret = send(sock_fd, data.get(), data_size, 0);

        close(sock_fd);
    }

    exit(EXIT_SUCCESS);
}