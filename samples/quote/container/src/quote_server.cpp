#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "acon_client.h"

using namespace std;

typedef struct {
    int32_t rtmr_log_offset;
    int32_t attestation_json_offset;
    int32_t data_offset;
    uint8_t data[0];
} quote_header;

class AconSocket {
    public:
        AconSocket() : socket_fd(-1) {
            ;
        }

        ~AconSocket() {
            if (this->socket_fd > 0) {
                close(this->socket_fd);
            }
        }

        size_t send_msg(void* msg_buf, size_t buf_size) {
            if (!msg_buf || buf_size == 0) {
                return -1;
            }

            if (this->socket_fd < 0 && this->connect() < 0) {
                return -1;
            }

            return write(this->socket_fd, msg_buf, buf_size);
        }

        size_t recv_msg(void** msg_buf) {
            if (!msg_buf) {
                return -1;
            }

            if (this->socket_fd < 0 && this->connect() < 0) {
                return -1;
            }

            size_t hdr_buf_size = sizeof(acon_message_hdr_t);
            void *hdr_buf = malloc(hdr_buf_size);
            if (!hdr_buf) {
                cerr << "Memory alloc error." << endl;
                return -1;
            }

            if (read(this->socket_fd, hdr_buf, hdr_buf_size) < hdr_buf_size) {
                cerr << "Response error." << endl;
                free(hdr_buf);
                return -1;
            }

            acon_message_hdr_t* msg_hdr = (acon_message_hdr_t*)hdr_buf;
            size_t total_size = msg_hdr->size;
            if (total_size < sizeof(acon_message_hdr_t)) {
                cerr << "Response error." << endl;
                free(hdr_buf);
                return -1;
            }

            void *resp_buf = malloc(total_size + 1);
            if (!resp_buf) {
                cerr << "Memory alloc error." << endl;
                free(hdr_buf);
                return -1;
            }

            memcpy(resp_buf, hdr_buf, hdr_buf_size);
            *((char *)resp_buf + total_size) = '\0';

            if (read(this->socket_fd, (char *)resp_buf + hdr_buf_size, total_size - hdr_buf_size) < 0) {
                cerr << "Response error." << endl;
                free(hdr_buf);
                free(resp_buf);
                return -1;
            }

            if (msg_hdr->command < 0) {
                cerr << (char *)((char *)resp_buf + sizeof(acon_message_err_t)) << "." << endl;
                free(hdr_buf);
                return -1;
            }

            free(hdr_buf);

            *msg_buf = resp_buf;
            return total_size;
        }

    private:
        int connect() {
            int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (socket_fd == -1) {
                cerr << "Socket error." << endl;
                return -1;
            }

            struct sockaddr_un client_addr;
            memset(&client_addr, 0, sizeof(client_addr));
            client_addr.sun_family = AF_UNIX;
            strncpy(client_addr.sun_path, SOCKET_PATH, sizeof(client_addr.sun_path) - 1);

            if (::connect(socket_fd, (struct sockaddr *)&client_addr, offsetof(struct sockaddr_un, sun_path) + 1 + strlen(SOCKET_PATH)) < 0) {
                cerr << "Server is down." << endl;
                return -1;
            }

            this->socket_fd = socket_fd;
            return this->socket_fd;
        }

    private:
        int socket_fd;
};

void get_quote(uint8_t** data, size_t *data_size) {
    const char* attest_data = "ATTEST DATA";
    size_t req_buf_size = sizeof(acon_get_report_req_t) + strlen(attest_data);
    acon_get_report_req_t *get_report_req = (acon_get_report_req_t *)malloc(req_buf_size);
    if (!get_report_req) {
        cerr << "Memory alloc error." << endl;
        exit(EXIT_FAILURE);
    }

    get_report_req->header.command = 0;
    get_report_req->header.size = req_buf_size;
    get_report_req->data_type = 1;
    get_report_req->nonce[0] = ((uint64_t)rand() << 32) | rand();
    get_report_req->nonce[1] = ((uint64_t)rand() << 32) | rand();
    get_report_req->attest_data_type = 2;
    memcpy(get_report_req + sizeof(acon_get_report_req_t), attest_data, strlen(attest_data));

    AconSocket socket;
    if (socket.send_msg((void *)get_report_req, req_buf_size) < 0) {
        cerr << "Request error." << endl;
        free(get_report_req);
        exit(EXIT_FAILURE);
    }
    free(get_report_req);

    void *resp_buf = NULL;
    if (socket.recv_msg(&resp_buf) < 0) {
        exit(EXIT_FAILURE);
    }

    acon_get_report_rsp_t *get_report_rsp = (acon_get_report_rsp_t *)resp_buf;
    if (get_report_rsp->attestation_json_offset > get_report_rsp->data_offset || get_report_rsp->data_offset > get_report_rsp->header.size) {
        cerr << "Response error." << endl;
        free(resp_buf);
        exit(EXIT_FAILURE);
    }

    size_t buf_size = sizeof(quote_header) + get_report_rsp->header.size - get_report_rsp->rtmr_log_offset;
    void *buf = malloc(buf_size);
    if (!buf) {
        cerr << "Memory alloc error." << endl;
        free(resp_buf);
        exit(EXIT_FAILURE);
    }

    quote_header *quote = (quote_header *)buf;
    quote->rtmr_log_offset = sizeof(quote_header);
    quote->attestation_json_offset = quote->rtmr_log_offset + get_report_rsp->attestation_json_offset - get_report_rsp->rtmr_log_offset;
    quote->data_offset = quote->attestation_json_offset + get_report_rsp->data_offset - get_report_rsp->attestation_json_offset;
    memcpy(quote->data, (void *)((uint8_t *)resp_buf + get_report_rsp->rtmr_log_offset), get_report_rsp->header.size - sizeof(acon_get_report_rsp_t));
    *data = (uint8_t*)buf;
    *data_size = buf_size;

    free(resp_buf);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(8085);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Server socket error." << endl;
        exit(EXIT_FAILURE);
    }

    if (bind(server_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Socket bind error." << endl;
        exit(EXIT_FAILURE);
    }

    while (1) {
        if (listen(server_fd, 1) < 0) {
            cerr << "Socket listen error." << endl;
            exit(EXIT_FAILURE);
        }

        struct sockaddr_in sock_addr;
        socklen_t sock_addr_size = sizeof(sock_addr);
        int sock_fd = accept(server_fd, (sockaddr *)&sock_addr, &sock_addr_size);
        if(sock_fd < 0) {
            cerr << "Accept request error." << endl;
            exit(EXIT_FAILURE);
        }

        uint8_t *data = NULL;
        size_t data_size = 0;
        get_quote(&data, &data_size);
        ssize_t ret = send(sock_fd, data, data_size, 0);

        free(data);
        close(sock_fd);
    }

    return 0;
}
