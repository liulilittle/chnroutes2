#include <stdio.h>
#include <io.h>
#include <time.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include <string>
#include <iostream>
#include <exception>

#include <set>
#include <vector>

#define APNIC_IP_FILE "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"
#define APNIC_KEY "apnic"
#define APNIC_NATION "CN"
#define APNIC_IP "ipv4"

#define PATH_IIP_NAME "china.txt"
#define SELF_APP_NAME "chnroutes2"

#ifndef F_OK 
#define F_OK 0
#endif

#pragma comment(lib, "WinMm.lib")

typedef
enum {
    Error_Success = 0,
    Error_FailedToCurlEasyInit,
    Error_NotAllowOpenUrlIsNullReferences,
    Error_FailedToCurlEasyPerform,
    Error_FailedToCurlEasyGetInfo,
    Error_NotAllowResponseBodyIsNullReferences,
    Error_NotAllowResponseHeadersIsNullReferences,
    Error_NotAllowResponseBodySizeIsNullReferences,
    Error_NotAllowResponseHeadersSizeIsNullReferences,
    Error_NotAllowStatusCodeIsNullReferences,
} Error;

typedef
struct {
    unsigned char* stream_;
    unsigned long	length_;
} WebResponseStream;

static void
curl_easy_free(const void* p) {
    if (NULL != p) {
        free((void*)p);
    }
}

static void*
curl_easy_relloc(const void* p, unsigned long sz) {
    if (sz == 0) {
        return NULL;
    }
    if (NULL == p) {
        return (void*)malloc(sz);
    }
    return (void*)realloc((void*)p, sz);
}

static size_t
curl_write_data(char* buf, size_t size, size_t nmemb, void* lpVoid) {
    size_t dw = size * nmemb;
    if (dw > 0 && NULL != lpVoid) {
        WebResponseStream* stream_ = (WebResponseStream*)lpVoid;
        if (NULL == stream_->stream_) {
            stream_->stream_ = (unsigned char*)curl_easy_relloc(NULL, dw + 1);
            stream_->length_ += dw;
            memcpy(stream_->stream_, buf, dw);
        }
        else {
            unsigned long stream_offset_ = stream_->length_;
            stream_->length_ += dw;
            stream_->stream_ = (unsigned char*)curl_easy_relloc(stream_->stream_, stream_->length_ + 1);
            memcpy(stream_->stream_ + stream_offset_, buf, dw);
        }
    }
    return dw;
}

static int
curl_easy_request(
    const char* open_url,
    long            connect_timeout,
    long            request_timeout,
    const char* request_headers,
    const char* request_body,
    int             request_body_size,
    unsigned char** response_body,
    unsigned long* response_body_size,
    unsigned char** response_headers,
    unsigned long* response_headers_size,
    long* status_code,
    const char* cacert_file_path,
    bool			support_verbose,
    bool			support_keep_alive,
    const char* request_user_agent,
    const char* auth_user_and_password) {
    if (NULL == open_url || *open_url == '\x0') {
        return Error::Error_NotAllowOpenUrlIsNullReferences;
    }

    if (NULL == response_body) {
        return Error::Error_NotAllowResponseBodyIsNullReferences;
    }

    if (NULL == response_headers) {
        return Error::Error_NotAllowResponseHeadersIsNullReferences;
    }

    if (NULL == response_body_size) {
        return Error::Error_NotAllowResponseBodySizeIsNullReferences;
    }

    if (NULL == response_headers_size) {
        return Error::Error_NotAllowResponseHeadersSizeIsNullReferences;
    }

    if (NULL == status_code) {
        return Error::Error_NotAllowStatusCodeIsNullReferences;
    }

    *response_body = NULL;
    *response_headers = NULL;
    *response_body_size = 0;
    *response_headers_size = 0;
    *status_code = 0;

    if (connect_timeout <= 0) {
        connect_timeout = 20L;
    }

    if (request_timeout <= 0) {
        request_timeout = 20L;
    }

    CURL* pCurl = curl_easy_init();
    if (NULL == pCurl) {
        return Error::Error_FailedToCurlEasyInit;
    }

    curl_slist* pslist = curl_slist_append(NULL, request_headers);
    if (NULL != pslist) {
        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, pslist);
    }

    curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, request_timeout); // 请求超时时长
    curl_easy_setopt(pCurl, CURLOPT_CONNECTTIMEOUT, connect_timeout);  // 连接超时时长 
    curl_easy_setopt(pCurl, CURLOPT_FOLLOWLOCATION, 1L); // 允许重定向
    curl_easy_setopt(pCurl, CURLOPT_HEADER, 1L);  // 若启用，会将头文件的信息作为数据流输出
    curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, curl_write_data);  // 得到请求结果后的回调函数

    WebResponseStream response_body_stream;
    WebResponseStream response_headers_stream;
    memset(&response_body_stream, 0, sizeof(response_body_stream));
    memset(&response_headers_stream, 0, sizeof(response_headers_stream));

    curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &response_body_stream);
    curl_easy_setopt(pCurl, CURLOPT_HEADERDATA, &response_headers_stream);
    curl_easy_setopt(pCurl, CURLOPT_NOSIGNAL, 1L); // 关闭中断信号响应
    if (support_verbose) {
        curl_easy_setopt(pCurl, CURLOPT_VERBOSE, 1L); // 启用时会汇报所有的信息
    }

    curl_easy_setopt(pCurl, CURLOPT_URL, open_url);
    curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1L);
    if (NULL != auth_user_and_password && *auth_user_and_password != '\x0') {
        curl_easy_setopt(pCurl, CURLOPT_USERPWD, auth_user_and_password);
    }

    if (NULL != request_user_agent && *request_user_agent != '\x0') {
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, request_user_agent);
    }

    if (NULL != request_body && request_body_size >= 0) {
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDSIZE, request_body_size);
    }

    if (support_keep_alive) {
        curl_easy_setopt(pCurl, CURLOPT_TCP_KEEPALIVE, 1L);
    }

    curl_easy_setopt(pCurl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(pCurl, CURLOPT_SSLENGINE_DEFAULT);
    if (NULL == cacert_file_path || *cacert_file_path == '\x0') {
        cacert_file_path = "cacert.pem";
    }

    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (_access(cacert_file_path, F_OK) == 0) {
        curl_easy_setopt(pCurl, CURLOPT_CAINFO, cacert_file_path);
    }

    Error error = Error::Error_Success;
    do {
        if (curl_easy_perform(pCurl) != CURLE_OK) {
            error = Error::Error_FailedToCurlEasyPerform;
            break;
        }

        if (curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, status_code) != CURLE_OK) {
            error = Error::Error_FailedToCurlEasyGetInfo;
            break;
        }

        *response_body = response_body_stream.stream_;
        *response_body_size = response_body_stream.length_;
        *response_headers = response_headers_stream.stream_;
        *response_headers_size = response_headers_stream.length_;

        if (NULL != *response_body && *response_body_size > 0) {
            (*response_body)[*response_body_size] = '\x0';
        }

        if (NULL != *response_headers && *response_headers_size > 0) {
            (*response_headers)[*response_headers_size] = '\x0';
        }
    } while (false);
    if (NULL != pslist) {
        curl_slist_free_all(pslist);
    }
    if (error != Error::Error_Success) {
        if (NULL != response_body_stream.stream_) {
            curl_easy_free(response_body_stream.stream_);
        }
        if (NULL != response_headers_stream.stream_) {
            curl_easy_free(response_headers_stream.stream_);
        }
    }
    curl_easy_cleanup(pCurl);
    return error;
}

static int
chnroutes2_tokenize(const std::string& str, std::vector<std::string>& tokens, const std::string& delimiters) {
    if (str.empty()) {
        return 0;
    }
    else if (delimiters.empty()) {
        tokens.push_back(str);
        return 1;
    }

    char* deli_ptr = (char*)delimiters.data();
    char* deli_endptr = deli_ptr + delimiters.size();
    char* data_ptr = (char*)str.data();
    char* data_endptr = data_ptr + str.size();
    char* last_ptr = NULL;

    int length = 0;
    int seg = 0;
    while (data_ptr < data_endptr) {
        int ch = *data_ptr;
        int b = 0;
        for (char* p = deli_ptr; p < deli_endptr; p++) {
            if (*p == ch) {
                b = 1;
                break;
            }
        }
        if (b) {
            if (seg) {
                int sz = data_ptr - last_ptr;
                if (sz > 0) {
                    length++;
                    tokens.push_back(std::string(last_ptr, sz));
                }
                seg = 0;
            }
        }
        else if (!seg) {
            seg = 1;
            last_ptr = data_ptr;
        }
        data_ptr++;
    }
    if ((seg && last_ptr) && last_ptr < data_ptr) {
        length++;
        tokens.push_back(std::string(last_ptr, data_ptr - last_ptr));
    }
    return length;
}

static std::string
chnroutes2_getiplist() {
    unsigned char* response_body;
    unsigned long response_body_size;
    unsigned char* response_headers;
    unsigned long reponse_headers_size;
    long status_code;
    int call_err = curl_easy_request(APNIC_IP_FILE, 0L, 0L,
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n"
        "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.104 Safari/537.36\r\n",
        NULL,
        0L,
        &response_body,
        &response_body_size,
        &response_headers,
        &reponse_headers_size,
        &status_code,
        NULL,
        false,
        true,
        NULL,
        NULL);

    std::string iplist;
    if (call_err != Error::Error_Success) {
        return std::move(iplist);
    }

    if (response_headers) {
        curl_easy_free(response_headers);
    }

    iplist = std::move(std::string((char*)response_body, response_body_size));
    if (response_body) {
        curl_easy_free(response_body);
    }
    return std::move(iplist);
}

static int
chnroutes2_getiplist(std::set<std::string>& out_, const std::string& iplist_) {
    if (iplist_.empty()) {
        return 0;
    }

    std::vector<std::string> lines_;
    chnroutes2_tokenize(iplist_, lines_, "\r\n");

    char fmt[260];
    sprintf_s(fmt, sizeof(fmt), "%s|%s|%s|%%d.%%d.%%d.%%d|%%d|%%d|allocated", APNIC_KEY, APNIC_NATION, APNIC_IP);

    int length_ = 0;
    for (size_t i = 0, l = lines_.size(); i < l; i++) {
        std::string& line_ = lines_[i];
        if (line_.empty()) {
            continue;
        }

        size_t pos = line_.find_first_of('#');
        if (pos == 0) {
            continue;
        }


        int ip[4];
        int cidr;
        int tm;
        int by = sscanf_s(line_.data(), fmt, ip, ip + 1, ip + 2, ip + 3, &cidr, &tm);
        if (by != 6) {
            continue;
        }

        int prefix = cidr ? 33 : 32;
        while (cidr) {
            cidr = cidr >> 1;
            prefix = prefix - 1;
        }

        char sz[1000];
        snprintf(sz, sizeof(sz), "%d.%d.%d.%d/%d", ip[0], ip[1], ip[2], ip[3], prefix);
        if (out_.insert(sz).second) {
            length_++;
        }
    }
    return length_;
}

static int
chnroutes2_getiplist(std::set<std::string>& out_) {
    std::string iplist_ = chnroutes2_getiplist();
    return chnroutes2_getiplist(out_, iplist_);
}

static bool
chnroutes2_saveiplist(const std::string& path_, const std::set<std::string>& ips_) {
    if (path_.empty()) {
        return false;
    }

    FILE* file_ = fopen(path_.c_str(), "wb+");
    if (NULL == file_) {
        return false;
    }

    std::string data_;
    std::set<std::string>::iterator tail_ = ips_.begin();
    std::set<std::string>::iterator endl_ = ips_.end();
    while (tail_ != endl_) {
        const std::string& line_ = *tail_++;
        data_.append(line_);
        data_.append("\n");
    }

    fwrite(data_.data(), data_.size(), 1, file_);
    fflush(file_);
    fclose(file_);
    return true;
}

static std::string
chnroutes2_gettime(time_t time_) {
    if (time_ == 0) {
        time_ = time(NULL);
    }

    struct tm tm_;
    localtime_s(&tm_, &time_);

    char sz[1000];
    sprintf_s(sz, sizeof(sz), "%04d-%02d-%02d %02d:%02d:%02d", 1900 + tm_.tm_year, 1 + tm_.tm_mon, tm_.tm_mday, tm_.tm_hour, tm_.tm_min, tm_.tm_sec);
    return sz;
}

static time_t
chnroutes2_gettime() {
    time_t tm_;
    timeBeginPeriod(1);
    tm_ = time(NULL);
    timeEndPeriod(1);
    return tm_;
}

static void
chnroutes2_sleep(int milliseconds) {
    if (milliseconds > 0) {
        timeBeginPeriod(1);
        Sleep(milliseconds);
        timeEndPeriod(1);
    }
}

int main(int argc, const char* argv[]) {
    SetConsoleTitle(TEXT(SELF_APP_NAME));
    SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentProcess(), THREAD_PRIORITY_LOWEST);

    std::string path_;
    if (argc > 1) {
        path_ = argv[1];
    }

    if (path_.empty()) {
        path_ = PATH_IIP_NAME;
    }

    time_t time_;
    time_t nowt_;
    time_t next_;
    for (; ;) {
        time_ = chnroutes2_gettime();
        printf("[%s]PULL\n", chnroutes2_gettime(time_).data());
        do {
            std::set<std::string> ips_;
            if (chnroutes2_getiplist(ips_)) {
                chnroutes2_saveiplist(path_, ips_);
            }
        } while (0);
        nowt_ = chnroutes2_gettime();
        printf("[%s]OK\n", chnroutes2_gettime(nowt_).data());

        next_ = 0;
        if (nowt_ >= time_) {
            next_ = nowt_ - time_;
            next_ = std::max<time_t>(0, 3600 - next_);
            next_ = next_ * 1000;
        }
        time_ = nowt_;
        chnroutes2_sleep((int)next_);
    }
    return 0;
}