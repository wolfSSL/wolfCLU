/* clu_http.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfclu/clu_header_main.h>

#include <wolfssl/test.h>

/* Platform-specific socket includes */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define SOCKADDR_IN_T struct sockaddr_in
    #define CLOSE_SOCKET(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #define SOCKADDR_IN_T struct sockaddr_in
    #define CLOSE_SOCKET(s) close(s)
    #define SOCKET_ERROR (-1)
#endif

/* Default HTTP GET request message */
static const char kDefaultHttpGet[] = "GET /index.html HTTP/1.0\r\n\r\n";

/* Default HTTP 200 OK response with HTML */
static const char kDefaultHttpResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "Content-Length: 141\r\n"
    "\r\n"
    "<html>\r\n"
    "<head>\r\n"
    "<title>Welcome to wolfSSL!</title>\r\n"
    "</head>\r\n"
    "<body>\r\n"
    "<p>wolfSSL has successfully performed handshake!</p>\r\n"
    "</body>\r\n"
    "</html>\r\n";

/**
 * @brief Get a simple HTTP GET request string
 * @return pointer to static HTTP GET request string
 */
const char* wolfCLU_GetDefaultHttpGet(void)
{
    return kDefaultHttpGet;
}

/**
 * @brief Get the length of the default HTTP GET request (without null terminator)
 * @return length of HTTP GET request
 */
int wolfCLU_GetDefaultHttpGetLength(void)
{
    return (int)(sizeof(kDefaultHttpGet) - 1);
}

/**
 * @brief Get a simple HTTP 200 OK response string with HTML content
 * @return pointer to static HTTP response string
 */
const char* wolfCLU_GetDefaultHttpResponse(void)
{
    return kDefaultHttpResponse;
}

/**
 * @brief Get the length of the default HTTP response (without null terminator)
 * @return length of HTTP response
 */
int wolfCLU_GetDefaultHttpResponseLength(void)
{
    return (int)(sizeof(kDefaultHttpResponse) - 1);
}

/**
 * @brief Build a custom HTTP GET request
 * @param path the path to request (e.g., "/index.html")
 * @param host optional host header value (can be NULL)
 * @param buffer buffer to write the request to
 * @param bufferSz size of the buffer
 * @return number of bytes written to buffer, or negative on error
 */
int wolfCLU_BuildHttpGet(const char* path, const char* host, char* buffer,
                         int bufferSz)
{
    int sz = 0;

    if (path == NULL || buffer == NULL || bufferSz < 32) {
        return -1;
    }

    /* Build GET request */
    sz = XSNPRINTF(buffer, bufferSz, "GET %s HTTP/1.0\r\n", path);
    if (sz < 0 || sz >= bufferSz) {
        return -1;
    }

    /* Add Host header if provided */
    if (host != NULL) {
        int hostSz = XSNPRINTF(buffer + sz, bufferSz - sz,
                               "Host: %s\r\n", host);
        if (hostSz < 0 || sz + hostSz >= bufferSz) {
            return -1;
        }
        sz += hostSz;
    }

    /* Add final CRLF */
    if (sz + 2 >= bufferSz) {
        return -1;
    }
    buffer[sz++] = '\r';
    buffer[sz++] = '\n';
    buffer[sz] = '\0';

    return sz;
}

/**
 * @brief Build a simple HTTP response
 * @param statusCode HTTP status code (e.g., 200, 404)
 * @param statusText HTTP status text (e.g., "OK", "Not Found")
 * @param contentType MIME type (e.g., "text/html")
 * @param body response body content
 * @param buffer buffer to write the response to
 * @param bufferSz size of the buffer
 * @return number of bytes written to buffer, or negative on error
 */
int wolfCLU_BuildHttpResponse(int statusCode, const char* statusText,
                              const char* contentType, const char* body,
                              char* buffer, int bufferSz)
{
    int sz = 0;
    int bodySz = 0;

    if (statusText == NULL || buffer == NULL || bufferSz < 64) {
        return -1;
    }

    if (body != NULL) {
        bodySz = (int)XSTRLEN(body);
    }

    /* Build status line */
    sz = XSNPRINTF(buffer, bufferSz, "HTTP/1.1 %d %s\r\n",
                   statusCode, statusText);
    if (sz < 0 || sz >= bufferSz) {
        return -1;
    }

    /* Add Content-Type header */
    if (contentType != NULL) {
        int ctSz = XSNPRINTF(buffer + sz, bufferSz - sz,
                            "Content-Type: %s\r\n", contentType);
        if (ctSz < 0 || sz + ctSz >= bufferSz) {
            return -1;
        }
        sz += ctSz;
    }

    /* Add Connection header */
    if (sz + 22 >= bufferSz) {
        return -1;
    }
    sz += XSNPRINTF(buffer + sz, bufferSz - sz, "Connection: close\r\n");

    /* Add Content-Length header */
    if (sz + 30 >= bufferSz) {
        return -1;
    }
    sz += XSNPRINTF(buffer + sz, bufferSz - sz, "Content-Length: %d\r\n",
                    bodySz);

    /* Add final CRLF before body */
    if (sz + 2 >= bufferSz) {
        return -1;
    }
    buffer[sz++] = '\r';
    buffer[sz++] = '\n';

    /* Add body if provided */
    if (body != NULL && bodySz > 0) {
        if (sz + bodySz >= bufferSz) {
            return -1;
        }
        XMEMCPY(buffer + sz, body, bodySz);
        sz += bodySz;
        buffer[sz] = '\0';
    }

    return sz;
}

/**
 * @brief Create and bind a server socket using tcp_listen
 * @param port port number to bind to (pointer will be updated with actual port)
 * @return socket descriptor on success, INVALID_SOCKET on error
 */
SOCKET_T wolfCLU_HttpServerListen(word16* port)
{
    SOCKET_T sockfd = INVALID_SOCKET;
    
    /* Use tcp_listen from wolfSSL test.h
     * Parameters:
     *   sockfd - socket to create
     *   port - port to bind to (pointer)
     *   useAnyAddr - 1 to use INADDR_ANY, 0 for localhost
     *   udp - 0 for TCP
     *   sctp - 0 for non-SCTP
     */
    tcp_listen(&sockfd, port, 1, 0, 0);
    
    return sockfd;
}

/**
 * @brief Accept a client connection
 * @param serverfd server socket descriptor
 * @return client socket descriptor on success, INVALID_SOCKET on error
 */
SOCKET_T wolfCLU_ServerAccept(SOCKET_T serverfd)
{
    SOCKADDR_IN_T clientAddr;
    socklen_t clientLen = sizeof(clientAddr);
    SOCKET_T clientfd;

    clientfd = accept(serverfd, (struct sockaddr*)&clientAddr, &clientLen);
    return clientfd;
}

/**
 * @brief Receive a complete HTTP request
 * @param clientfd client socket descriptor
 * @param buffer buffer to store request
 * @param bufferSz size of buffer
 * @return number of bytes received, or negative on error
 */
int wolfCLU_HttpServerRecv(SOCKET_T clientfd, byte* buffer, int bufferSz)
{
    int totalLen = 0;
    int contentLen = 0;
    int headerSz = 0;

    while (totalLen < bufferSz - 1) {
        int n = (int)recv(clientfd, (char*)buffer + totalLen,
                     (size_t)(bufferSz - 1 - totalLen), 0);
        if (n <= 0)
            break;
        totalLen += n;
        buffer[totalLen] = '\0';

        /* Once we find end-of-headers, parse Content-Length */
        if (headerSz == 0) {
            const char* hdrEnd = XSTRSTR((char*)buffer, "\r\n\r\n");
            if (hdrEnd != NULL) {
                const char* cl;
                headerSz = (int)(hdrEnd + 4 - (char*)buffer);
                cl = XSTRSTR((char*)buffer, "Content-Length:");
                if (cl == NULL)
                    cl = XSTRSTR((char*)buffer, "content-length:");
                if (cl != NULL) {
                    contentLen = XATOI(cl + 15);
                    if (contentLen < 0)
                        contentLen = 0;
                }
            }
        }
        /* Check if we have the full body */
        if (headerSz > 0 && totalLen >= headerSz + contentLen)
            break;
    }
    return totalLen;
}

/* Send all bytes, looping on partial writes and EINTR */
int wolfCLU_SendAll(SOCKET_T sockfd, const char* buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = (int)send(sockfd, buf + sent, (size_t)(len - sent), 0);
        if (n < 0) {
#ifndef _WIN32
            if (errno == EINTR) continue;
#endif
            return -1;
        }
        if (n == 0)
            return -1;
        sent += n;
    }
    return sent;
}

/**
 * @brief Send an HTTP response with OCSP content
 * @param clientfd client socket descriptor
 * @param body response body (OCSP response)
 * @param bodySz size of response body
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerSendOcspResponse(SOCKET_T clientfd, const byte* body,
                                        int bodySz)
{
    char header[512];
    int headerLen;

    headerLen = XSNPRINTF(header, sizeof(header),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", bodySz);

    if (headerLen < 0 || headerLen >= (int)sizeof(header)) {
        return -1;
    }

    /* Send header */
    if (wolfCLU_SendAll(clientfd, header, headerLen) != headerLen) {
        return -1;
    }

    /* Send body */
    if (bodySz > 0) {
        if (wolfCLU_SendAll(clientfd, (const char*)body, bodySz) != bodySz) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Send an HTTP error response
 * @param clientfd client socket descriptor
 * @param statusCode HTTP status code
 * @param statusMsg HTTP status message
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerSendError(SOCKET_T clientfd, int statusCode,
                                 const char* statusMsg)
{
    char response[512];
    int len;
    int msgLen = (int)XSTRLEN(statusMsg);

    len = XSNPRINTF(response, sizeof(response),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", statusCode, statusMsg, msgLen, statusMsg);

    if (len < 0 || len >= (int)sizeof(response)) {
        return -1;
    }

    return (send(clientfd, response, (size_t)len, 0) == len) ? 0 : -1;
}

/**
 * @brief Close a socket
 * @param sockfd socket descriptor to close
 */
void wolfCLU_ServerClose(SOCKET_T sockfd)
{
    if (sockfd != INVALID_SOCKET) {
        CLOSE_SOCKET(sockfd);
    }
}

/**
 * @brief Parse HTTP POST request to extract OCSP request body
 * @param httpReq HTTP request buffer
 * @param httpReqSz size of HTTP request
 * @param body pointer to store body location (output)
 * @param bodySz pointer to store body size (output)
 * @return 0 on success, negative on error
 */
int wolfCLU_HttpServerParseRequest(const byte* httpReq, int httpReqSz,
                                    const byte** body, int* bodySz)
{
    const char* contentLen;
    const char* bodyStart;
    int bodyAvail;

    *body = NULL;
    *bodySz = 0;

    if (httpReqSz < (int)XSTR_SIZEOF("POST ")) {
        return -1;
    }

    /* Check for POST method */
    if (XSTRNCMP((char*)httpReq, "POST ", 
                 XSTR_SIZEOF("POST ")) != 0) {
        return -1;
    }

    /* Find Content-Length */
    contentLen = XSTRSTR((char*)httpReq, "Content-Length:");
    if (contentLen == NULL) {
        contentLen = XSTRSTR((char*)httpReq, "content-length:");
    }
    if (contentLen) {
        *bodySz = XATOI(contentLen + XSTR_SIZEOF("Content-Length:"));
        if (*bodySz <= 0) {
            return -1;
        }
    }

    /* Find body (has to appear after headers) */
    bodyStart = XSTRSTR((char*)contentLen, "\r\n\r\n");
    if (!bodyStart)
        return -1;
    bodyAvail = (int)(((char*)httpReq + httpReqSz) - 
        (bodyStart + XSTR_SIZEOF("\r\n\r\n")));
    /* Use Content-Length if available, otherwise use
     * remaining data. Verify how much body we have. */
    if (*bodySz == 0) {
        *bodySz = bodyAvail;
    }
    else if (*bodySz > bodyAvail) {
        return -1;
    }
    *body = (const byte*)(bodyStart + XSTR_SIZEOF("\r\n\r\n"));
    return 0;
}
