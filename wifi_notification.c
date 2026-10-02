#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/dns.h"
#include "lwip/altcp_tls.h"
#include "mbedtls/ssl.h"
#include "altcp_tls_mbedtls_structs.h"

#include "wifi_notification.h"

#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

static struct altcp_pcb* https_pcb = NULL;
static struct altcp_tls_config* config =  NULL;
static volatile bool request_complete = false;
static volatile bool request_success = false;
static volatile bool https_connection = false;
static volatile bool connection_failed = false;

bool connect_to_wifi(void){
    cyw43_arch_enable_sta_mode();
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) 
        return false; 
    return true;
}

bool resolve_hostname(ip_addr_t* ipaddr) {
    ipaddr->addr = IPADDR_ANY;
    cyw43_arch_lwip_begin();
    err_t lwip_err = dns_gethostbyname(HOSTNAME, ipaddr, callback_gethostbyname, ipaddr);
    cyw43_arch_lwip_end();
    
    if (lwip_err == ERR_INPROGRESS) {
        while (ipaddr->addr == IPADDR_ANY)
            sleep_ms(500);
        if (ipaddr->addr != IPADDR_NONE)
            lwip_err = ERR_OK;
    }
    return !(bool)lwip_err;
}

void callback_gethostbyname(
    const char* name,
    const ip_addr_t* resolved,
    void* ipaddr
){
    if(resolved) *((ip_addr_t*)ipaddr) = *resolved;         // Successful resolution
    else ((ip_addr_t*)ipaddr)->addr = IPADDR_NONE;          // Failed resolution
}

bool connect_to_host(ip_addr_t* ipaddr) {
    u8_t ca_cert[] = CA_ROOT_CERT;
    size_t cert_len = sizeof(ca_cert);
    if (!validate_cert(ca_cert, cert_len))
        return false;
    
    cyw43_arch_lwip_begin();
    config = altcp_tls_create_config_client(ca_cert, cert_len);
    // if (config==NULL) {
    //     printf("TLS config failed, continuing without certificate.\n");
    //     config = altcp_tls_create_config_client(NULL, 0);
    // }
    
    https_pcb = altcp_tls_new(config, IPADDR_TYPE_V4);
    cyw43_arch_lwip_end();
    if(https_pcb == NULL){
        altcp_tls_free_config(config);
        return false;
    }

    // Set SNI hostname
    cyw43_arch_lwip_begin();
    //int mbedtls_err = mbedtls_ssl_set_hostname(&(((altcp_mbedtls_state_t*)((*pcb)->state))->ssl_context), HOSTNAME);
    int mbedtls_err = mbedtls_ssl_set_hostname(altcp_tls_context(https_pcb), HOSTNAME);
    cyw43_arch_lwip_end();
    if(mbedtls_err){
        altcp_close(https_pcb);
        altcp_tls_free_config(config);
        return false;
    }

    // Set callback functions
    cyw43_arch_lwip_begin();
    altcp_arg(https_pcb, NULL);
    altcp_err(https_pcb, callback_altcp_err);
    altcp_recv(https_pcb, callback_altcp_recv);

    // Connect to host
    printf("Attempting to connect to host.\n");

    err_t err = altcp_connect(https_pcb, ipaddr, HTTPS_PORT, callback_altcp_connect);
    cyw43_arch_lwip_end();
    if (err != ERR_OK)
    {
        printf("altcp_connect failed: %d\n", err);
        altcp_abort(https_pcb);
        altcp_tls_free_config(config);
        https_pcb = NULL;
        request_complete = true;
        request_success = false;
        return false;
    }
    while (!https_connection && !connection_failed) {
        cyw43_arch_poll();
        sleep_ms(10);
    }
    if (!https_connection) {
        printf("TLS connection failed.\n");
        return false;
    }
    return true;
}

bool validate_cert(const uint8_t *ca_cert, size_t cert_len) {
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);

    int ret = mbedtls_x509_crt_parse(
        &cert,
        ca_cert,
        cert_len
    );

    if (ret != 0) {
        char error_buf[128];

        mbedtls_strerror(
            ret,
            error_buf,
            sizeof(error_buf)
        );

        printf("Certificate parse failed: -0x%04x\n",
            (unsigned int)-ret);

        printf("mbedtls error: %s\n", error_buf);
        mbedtls_x509_crt_free(&cert);
        return false;
    } else {
        printf("Certificate parsed successfully.\n");
        mbedtls_x509_crt_free(&cert);
        return true;
    }
}

bool send_request() {
    const char request[] = HTTPS_REQUEST;
    request_complete = false;
    request_success = false;

    //write request
    cyw43_arch_lwip_begin();
    err_t err = altcp_write(https_pcb, request, strlen(request), TCP_WRITE_FLAG_COPY);
    cyw43_arch_lwip_end();
    if (err != ERR_OK) {
        printf("Write request failed: %d\n", err);
        request_complete = true;
        request_success = false;
        return false;
    }
    //send request
    cyw43_arch_lwip_begin();
    err = altcp_output(https_pcb);
    cyw43_arch_lwip_end();
    if (err != ERR_OK) {
        printf("Error sending request: %d\n", err);
        request_complete = true;
        request_success = false;
        return false;
    }
    printf("HTTP request transmitted. Waiting for response...\n");
    while (!request_complete) {
        cyw43_arch_poll();
        sleep_ms(10);
    }
    if (!request_success) {
        printf("No response received\n");
        return false;
    }
    printf("HTTP response received successfully.\n");
    return true;
}

err_t callback_altcp_connect(
    void* arg,
    struct altcp_pcb* pcb,
    err_t err
){
    if (err != ERR_OK) {
        printf("Connection to host failed: %d\n", err);
        request_complete = true;
        request_success = false;
        https_connection = false;
        connection_failed = true;
        return err;
    }
    printf("Connection to host established.\n");
    https_connection = true;
    connection_failed = false;
    return ERR_OK;
}

void callback_altcp_err(void* arg, err_t err) {
    printf("Connection error: %d\n", err);
    request_complete = true;
    request_success = false;
    https_connection = false;
    connection_failed = true;
}

err_t callback_altcp_recv(
    void* arg,
    struct altcp_pcb* pcb,
    struct pbuf* buf,
    err_t err
){
    if (err != ERR_OK) {
        printf("Receive error: %d\n", err);

        request_success = false;
        request_complete = true;

        return err;
    }

    if (buf == NULL) {
        printf("Connection close.\n");
        request_complete = true;
        if (pcb != NULL)
            altcp_close(pcb);
        https_pcb = NULL;
        return ERR_OK;
    }
    if (buf->tot_len > 0) {
        char buffer[512];
        uint16_t length = buf->tot_len;
        if (length >= sizeof(buffer))
            length = sizeof(buffer) - 1;

        pbuf_copy_partial(buf, buffer, length, 0);
        buffer[length] = '\0';
        printf("Response:\n%s\n", buffer);
        
        altcp_recved(pcb, buf->tot_len);
        request_success = true;
        request_complete = true;
    }
    pbuf_free(buf);
    return ERR_OK;
}


int main()
{
    stdio_init_all();

    // wait for usb connection
    while (!stdio_usb_connected()) {
        sleep_ms(1000);
    }

    // Initialize CYW43
    if (cyw43_arch_init()) {
        printf("Initializing CYW43\n");
        return -1;
    }
    printf("Initialized CYW43\n");

    // Connect to Wifi
    printf("Connecting to Wi-Fi...\n");
    if (!connect_to_wifi()) {
        printf("WiFi connection failed\n");
        cyw43_arch_deinit();
        return -1;
    }
    printf("WiFi connected\n");

    // Resolve hostname to IP
    ip_addr_t ipaddr;
    printf("Resolving %s\n", HOSTNAME);
    if (!resolve_hostname(&ipaddr)) {
        printf("Failed to resolve hostname\n");
        cyw43_arch_deinit();
        return -1;
    }
    char* char_ipaddr;
    char_ipaddr = ipaddr_ntoa(&ipaddr);
    printf("Resolved hostname to %s\n", char_ipaddr);

    // TLS connection with host
    
    if (!connect_to_host(&ipaddr)) {
        printf("Failed to connect.\n");
        cyw43_arch_deinit();
        return -1;
    }
    if (https_connection) printf("Connected to https://%s\n", char_ipaddr);

    if (!send_request()) {
        printf("Failed to send request.\n");
        altcp_tls_free_config(config);
        altcp_close(https_pcb);
        cyw43_arch_deinit();
        return -1;
    }
    printf("Request sent\n");

    // might need delete request_connection: if used in connect_to_host to wait for connection it hangs

    while (true) {
        cyw43_arch_poll();
        sleep_ms(1000);
    }

    cyw43_arch_deinit();
}
