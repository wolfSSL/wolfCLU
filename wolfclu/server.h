#define NO_MAIN_DRIVER

#ifndef WOLFCLU_NO_FILESYSTEM
THREAD_RETURN WOLFSSL_THREAD server_test(void* args);

int ServerEchoData(WOLFSSL* ssl, int clientfd, int echoData, int blockSize,
                   size_t benchmarkThroughput);
#endif