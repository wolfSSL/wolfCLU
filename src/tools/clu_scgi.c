/* clu_scgi.c
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

/*
 * SCGI (Simple Common Gateway Interface) Protocol Implementation
 *
 * Following the specification at https://python.ca/scgi/protocol.txt
 *
 * SCGI is a protocol for communication between web servers and application
 * servers. It's simpler than FastCGI but provides similar functionality.
 *
 * Wire Format:
 * ------------
 * Request:  <netstring-length>:<headers>,<body>
 *
 * Where:
 *   <netstring-length> : ASCII decimal number of bytes in headers section
 *   :                   : Literal colon separator
 *   <headers>          : Null-separated key-value pairs (key\0value\0...)
 *   ,                   : Literal comma separator (end of headers)
 *   <body>             : Raw body bytes
 *
 * Example Request:
 *   70:CONTENT_LENGTH\027\0SCGI\01\0REQUEST_METHOD\0POST\0REQUEST_URI\0/deepthought\0,What is the answer to life?
 *
 * Response Format:
 * ---------------
 * Standard CGI response with Status and headers:
 *   Status: 200 OK\r\n
 *   Content-Type: application/ocsp-response\r\n
 *   \r\n
 *   <response body>
 */

#include <wolfclu/clu_header_main.h>
#include <wolfclu/clu_log.h>

/* Platform-specific includes for sockets */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
#endif

/* Read exactly n bytes from socket, handling partial reads */
static int readExactly(SOCKET_T sockfd, byte* buffer, int n)
{
    int totalRead = 0;
    
    while (totalRead < n) {
        int ret = (int)recv(sockfd, (char*)buffer + totalRead, n - totalRead, 0);
        if (ret <= 0) {
            return -1;
        }
        totalRead += ret;
    }
    return totalRead;
}

/* Parse netstring length (read until ':' and convert to integer) */
static int parseNetstringLength(SOCKET_T sockfd, int* length)
{
    char lenBuf[16];
    int i = 0;
    
    *length = 0;
    
    while (i < (int)sizeof(lenBuf) - 1) {
        int ret = (int)recv(sockfd, &lenBuf[i], 1, 0);
        if (ret <= 0) {
            return -1;
        }
        if (lenBuf[i] == ':') {
            lenBuf[i] = '\0';
            *length = XATOI(lenBuf);
            if (*length < 0) {
                return -1;
            }
            return 0;
        }
        i++;
    }
    
    return -1;
}

/* Parse SCGI headers (null-separated key-value pairs) */
static int parseHeaders(const byte* headers, int headerLen, ScgiRequest* req)
{
    int pos = 0;
    
    req->contentLength = -1;
    req->requestMethod = NULL;
    req->requestUri = NULL;
    
    while (pos < headerLen) {
        const char* key = (const char*)(headers + pos);
        const char* keyEnd;
        const char* value;
        const char* valueEnd;
        int keyLen;
        int valueLen;

        /* Find NUL terminator for key within remaining bounds */
        keyEnd = (const char*)memchr(key, '\0', (size_t)(headerLen - pos));
        if (keyEnd == NULL) {
            break;
        }
        keyLen = (int)(keyEnd - key);
        pos += keyLen + 1;

        if (pos >= headerLen) {
            break;
        }

        /* Find NUL terminator for value within remaining bounds */
        value = (const char*)(headers + pos);
        valueEnd = (const char*)memchr(value, '\0', (size_t)(headerLen - pos));
        if (valueEnd == NULL) {
            break;
        }
        valueLen = (int)(valueEnd - value);
        
        if (XSTRCMP(key, "CONTENT_LENGTH") == 0) {
            req->contentLength = XATOI(value);
        }
        else if (XSTRCMP(key, "REQUEST_METHOD") == 0) {
            req->requestMethod = value;
        }
        else if (XSTRCMP(key, "REQUEST_URI") == 0) {
            req->requestUri = value;
        }
        else {
            WOLFCLU_LOG(WOLFCLU_L2, "Got unsupported SCGI header");
        }
        
        pos += valueLen + 1;
    }
    
    return 0;
}

/**
 * @brief Read and parse an SCGI request from socket
 * @param sockfd socket descriptor
 * @param buffer buffer to store the complete request
 * @param bufferSz size of buffer
 * @param req output structure to store parsed request
 * @return 0 on success, negative on error
 */
int wolfCLU_ScgiReadRequest(SOCKET_T sockfd, byte* buffer, int bufferSz,
                             ScgiRequest* req)
{
    int headerLen;
    int pos = 0;
    byte comma;
    
    XMEMSET(req, 0, sizeof(ScgiRequest));
    
    if (parseNetstringLength(sockfd, &headerLen) != 0) {
        WOLFCLU_LOG(WOLFCLU_E0, "Failed to parse SCGI netstring length");
        return -1;
    }
    
    if (headerLen <= 0 || headerLen >= bufferSz) {
        WOLFCLU_LOG(WOLFCLU_E0, "Invalid SCGI header length: %d", headerLen);
        return -1;
    }
    
    if (readExactly(sockfd, buffer, headerLen) != headerLen) {
        WOLFCLU_LOG(WOLFCLU_E0, "Failed to read SCGI headers");
        return -1;
    }
    pos = headerLen;
    
    if (readExactly(sockfd, &comma, 1) != 1 || comma != ',') {
        WOLFCLU_LOG(WOLFCLU_E0, "Invalid SCGI netstring terminator");
        return -1;
    }
    
    if (parseHeaders(buffer, headerLen, req) != 0) {
        WOLFCLU_LOG(WOLFCLU_E0, "Failed to parse SCGI headers");
        return -1;
    }
    
    if (req->contentLength < 0 || pos + req->contentLength > bufferSz) {
        WOLFCLU_LOG(WOLFCLU_E0, "Invalid SCGI content length: %d", 
                    req->contentLength);
        return -1;
    }
    
    if (req->contentLength > 0) {
        if (readExactly(sockfd, buffer + pos, req->contentLength) != 
            req->contentLength) {
            WOLFCLU_LOG(WOLFCLU_E0, "Failed to read SCGI body");
            return -1;
        }
        req->body = buffer + pos;
        req->bodyLen = req->contentLength;
    }
    else {
        req->body = NULL;
        req->bodyLen = 0;
    }
    
    return 0;
}

/**
 * @brief Send SCGI response with status and body
 * @param sockfd socket descriptor
 * @param statusCode HTTP status code
 * @param statusText HTTP status text
 * @param contentType MIME type
 * @param body response body
 * @param bodyLen size of response body
 * @return 0 on success, negative on error
 */
int wolfCLU_ScgiSendResponse(SOCKET_T sockfd, int statusCode,
                              const char* statusText, const char* contentType,
                              const byte* body, int bodyLen)
{
    char header[512];
    int headerLen;
    
    headerLen = XSNPRINTF(header, sizeof(header),
        "Status: %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        statusCode, statusText, contentType, bodyLen);
    
    if (headerLen < 0 || headerLen >= (int)sizeof(header)) {
        return -1;
    }
    
    if (wolfCLU_SendAll(sockfd, header, headerLen) != headerLen) {
        return -1;
    }
    
    if (bodyLen > 0 && body != NULL) {
        if (wolfCLU_SendAll(sockfd, (const char*)body, bodyLen) != bodyLen) {
            return -1;
        }
    }
    
    return 0;
}

/**
 * @brief Send SCGI error response
 * @param sockfd socket descriptor
 * @param statusCode HTTP status code
 * @param statusText HTTP status text (also used as body)
 * @return 0 on success, negative on error
 */
int wolfCLU_ScgiSendError(SOCKET_T sockfd, int statusCode,
                           const char* statusText)
{
    return wolfCLU_ScgiSendResponse(sockfd, statusCode, statusText,
                                     "text/plain",
                                     (const byte*)statusText,
                                     (int)XSTRLEN(statusText));
}
