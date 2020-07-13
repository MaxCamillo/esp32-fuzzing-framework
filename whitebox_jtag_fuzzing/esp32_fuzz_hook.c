#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TARGET_ADDRESS "localhost"
#define TARGET_PORT 8082
#define BUFFER_SIZE 1024 * 1024 //1MB enough?

#define OPENOCD_ADDRESS "127.0.0.1"
#define OPENOCD_PORT 4444
#define OPENOCD_BUFFER_SIZE 1024 * 2

/* Defines from gcov */
#define GCOV_DATA_MAGIC ((uint32_t)0x67636461) /* "gcda" */
#define GCOV_TAG_FUNCTION ((uint32_t)0x01000000)
#define GCOV_TAG_FUNCTION_LENGTH (3 * 4) // 3 * 4 bytes
#define GCOV_TAG_OBJECT_SUMMARY ((uint32_t)0xa1000000)
#define GCOV_TAG_PROGRAM_SUMMARY ((uint32_t)0xa3000000)
#define GCOV_TAG_COUNTER_BASE ((uint32_t)0x01a10000)

#define GCOV_COUNTERS 1
/* Convert a tag to a counter.  */
#define GCOV_COUNTER_FOR_TAG(TAG) \
    ((unsigned)(((TAG)-GCOV_TAG_COUNTER_BASE) >> 17))
/* Check whether a tag is a counter tag.  */
#define GCOV_TAG_IS_COUNTER(TAG) \
    (!((TAG)&0xFFFF) && GCOV_COUNTER_FOR_TAG(TAG) < GCOV_COUNTERS)

//http request ending
const char *http_crlf = "\r\n";

//List of code_covarage files to evaluate
const char *CODE_COVERAGE_FILES[] = 
{
    "./example_esp32_server/build/esp-idf/main/CMakeFiles/__idf_main.dir/main.c.gcda",
    "./example_esp32_server/build/esp-idf/nghttp/CMakeFiles/__idf_nghttp.dir/port/http_parser.c.gcda",
};

//hongfuzz library functions
extern void HonggfuzzFetchData(const uint8_t **buf_ptr, size_t *len_ptr);
extern void instrumentClearNewCov();
void hfuzz_trace_pc(uintptr_t pc);
extern void hfuzzInstrumentInit(void);

/**
 * Fetch data, send it to target, check liveness
 * */
void sendOneRequest()
{

    //socket to target
    int target_sockfd;
    struct sockaddr_in target_sock_addr;
    struct hostent *hp;

    //Send and receive buffer
    char buf[BUFFER_SIZE]; //TODO Determine buffer size
    int len;

    const uint8_t *fuzz_string = (uint8_t *)"";
    size_t fuzz_len = 0;

    //get fuzzing string from honggfuzz
    HonggfuzzFetchData(&fuzz_string, &fuzz_len);

    if (fuzz_len > BUFFER_SIZE - strlen(http_crlf))
    {
        printf("Fuzzer data too big!! \n");
        return;
    }

    //concatenate fuzzer string + http header and save to buf
    //snprintf(buf, sizeof buf, "%s%s", fuzz_string, http_crlf);
    memcpy(buf, fuzz_string, fuzz_len * sizeof(uint8_t));
    memcpy(buf + fuzz_len * sizeof(uint8_t), http_crlf, (strlen(http_crlf) + 1) * sizeof(char));

    printf("Send data: \n");
    fwrite(buf, strlen(buf) + 1, 1, stdout);

    //create socket to target
    target_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (target_sockfd < 0)
    {
        perror("ERROR opening target socket");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 8;
    tv.tv_usec = 0;
    if (setsockopt(target_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv))
    {
        perror("ERROR set target socket option");
        exit(1);
    }

    int val = 1;
    if (setsockopt(target_sockfd, SOL_SOCKET, SO_REUSEADDR, &val, (socklen_t)sizeof(val)) == -1)
    {
        perror("ERROR set target socket option");
    }

    val = 1;
    if (setsockopt(target_sockfd, SOL_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val)) == -1)
    {
        perror("ERROR set target socket option");
        exit(1);
    }

    val = 1;
    if (setsockopt(target_sockfd, SOL_TCP, TCP_QUICKACK, &val, (socklen_t)sizeof(val)) == -1)
    {
        perror("ERROR set target socket option");
        exit(1);
    }

    /* get internet address of host specified by command line */
    hp = gethostbyname(TARGET_ADDRESS);
    if (hp == NULL)
    {
        perror("ERROR resolve target");
        exit(1);
    }

    bzero(&target_sock_addr, sizeof(target_sock_addr));
    target_sock_addr.sin_family = AF_INET;
    target_sock_addr.sin_port = htons(TARGET_PORT);
    bcopy(hp->h_addr, &target_sock_addr.sin_addr, hp->h_length);

    //Connect to target
    if (connect(target_sockfd, (struct sockaddr *)&target_sock_addr, sizeof(target_sock_addr)) < 0)
    {
        perror("connect to target failed. Error");
        exit(1);
    }

    //send request
    int sent = send(target_sockfd, buf, strlen(buf) + 1, 0);
    printf("%i \n", sent);

    //Read response to avoid full buffers of target
    len = read(target_sockfd, buf, BUFFER_SIZE);
    printf("%i %i\n", len, h_errno);
    if (len == -1)
    {
        raise(SIGSEGV);
    }
    else if (len == 0)
    {
        //raise(SIGSEGV);
    }

    close(target_sockfd);

    //Liveness check - connect again to target
    // target_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // if (target_sockfd < 0)
    // {
    //     //perror("ERROR opening target socket");
    //     raise(SIGSEGV);
    // }
    // if (connect(target_sockfd, (struct sockaddr *)&target_sock_addr, sizeof(target_sock_addr)) < 0)
    // {
    //     //perror("connect to target failed. Target down?");
    //     raise(SIGSEGV);
    // }

    // close(target_sockfd);
}

uint32_t read_uint32t(FILE *file)
{
    uint32_t value;
    fread(&value, sizeof(uint32_t), 1, file);
    return value;
}

uint64_t read_uint64t(FILE *file)
{
    uint64_t value;
    fread(&value, sizeof(uint64_t), 1, file);
    return value;
}

void parse_gcov_file(const char *filename, uint64_t *pseudoPC)
{


    //open coverage file as binary file
    FILE *coverage_file = fopen(filename, "rb");

    if (coverage_file == NULL)
    {
        perror("Failed to open coverage file. Error");
    }

    uint32_t magic = read_uint32t(coverage_file);

    if (magic != GCOV_DATA_MAGIC)
    {
        perror("Magic of coverage file does not match!. Error");
        fclose(coverage_file);
        return;
    }

    uint32_t version = read_uint32t(coverage_file);
    //printf("version: %x \n", version);

    //stamp
    uint32_t tag = read_uint32t(coverage_file);
    //printf("stamp: %x \n", tag);

    while (tag = read_uint32t(coverage_file))
    {
        //get length of block in bytes
        uint32_t length = read_uint32t(coverage_file) * 4;
        unsigned long base = ftell(coverage_file);

        if (tag == GCOV_TAG_PROGRAM_SUMMARY)
        {

            //not interesting for us
            fseek(coverage_file, length, SEEK_CUR);
        }
        else if (tag == GCOV_TAG_OBJECT_SUMMARY)
        {

            // uint32_t runs = read_uint32t(coverage_file);
            // uint32_t sum_max = read_uint32t(coverage_file);

            // printf("Runs/SumMax: %i / %i \n", runs, sum_max);
            //not interesting for us
            fseek(coverage_file, length, SEEK_CUR);
        }
        else if (tag == GCOV_TAG_FUNCTION && length == GCOV_TAG_FUNCTION_LENGTH)
        {
            //not interesting for us
            fseek(coverage_file, length, SEEK_CUR);
        }
        else if (GCOV_TAG_IS_COUNTER(tag))
        {

            //read 8 byte counter values
            for (int ix = 0; ix < length / 8; ix++)
            {
                uint64_t counter = read_uint64t(coverage_file);
                if (counter > 0)
                {
                    hfuzz_trace_pc((*pseudoPC));
                }
                *pseudoPC = (*pseudoPC) + 1;
            }
        }
        else
        {
            printf("No Tag matched? %x \n", tag);
        }

        unsigned long current_pos = ftell(coverage_file);

        if (current_pos != base + length)
        {
            printf("Sync fail: %ld - %ld \n", current_pos, base + length);
        }
    }

    fclose(coverage_file);
}

void evaluate_coverage_files() {
    //needed to use simulate trace_pc for honggfuzz interface
    uint64_t pseudoPC = 0;

    for (int i = 0; i < sizeof CODE_COVERAGE_FILES / sizeof *CODE_COVERAGE_FILES; i++)
    {
        parse_gcov_file(CODE_COVERAGE_FILES[i], &pseudoPC);
    }
    
                
}

void whitebox_fuzzing()
{
    printf("Whitebox_Fuzzing");

    //TODO check for neccessary init functions
    hfuzzInstrumentInit();
    instrumentClearNewCov();

    int openocd_sockfd;
    struct sockaddr_in openocd_sock_addr;
    struct hostent *openocd_hp;

    char buf[OPENOCD_BUFFER_SIZE];
    int len;

    //Telnet connection to openocd
    //create socket to openocd
    openocd_sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (openocd_sockfd < 0)
    {
        perror("ERROR opening openocd socket");
        exit(1);
    }

    /* get internet address of host specified by command line */
    openocd_hp = gethostbyname(OPENOCD_ADDRESS);
    if (openocd_hp == NULL)
    {
        perror("ERROR resolve openocd");
        exit(1);
    }

    bzero(&openocd_sock_addr, sizeof(openocd_sock_addr));
    openocd_sock_addr.sin_family = AF_INET;
    openocd_sock_addr.sin_port = htons(OPENOCD_PORT);
    bcopy(openocd_hp->h_addr, &openocd_sock_addr.sin_addr, openocd_hp->h_length);

    //Connect to openocd
    if (connect(openocd_sockfd, (struct sockaddr *)&openocd_sock_addr, sizeof(openocd_sock_addr)) < 0)
    {
        perror("connect to openocd failed. Error");
        exit(1);
    }

    while (1)
    {

        sendOneRequest();

        usleep(50000);
        //get coverage from openocd
        snprintf(buf, sizeof buf, "esp32 gcov\n");
        int sent = send(openocd_sockfd, buf, strlen(buf) + 1, 0);

        //usleep(100000);
        //Read response //TODO smarter solution?
        while (strstr(buf, "Targets disconnected.") == 0)
        {
            len = read(openocd_sockfd, buf, OPENOCD_BUFFER_SIZE);
            if (len == -1)
            {
                perror("receive from openocd failed. Error");
                exit(1);
            }
            else if (len == 0)
            {
                perror("openocd closed connection?. Error");
                exit(1);
            }
        }

        //translate coverage to honggfuzz
        evaluate_coverage_files();
    }

    close(openocd_sockfd);
}

void blackbox_fuzzing()
{

    while (1)
    {
        sendOneRequest();
    }
}

int main(int argc, char *argv[])
{


    //remove eventually old coverage files
    for (int i = 0; i < sizeof CODE_COVERAGE_FILES / sizeof *CODE_COVERAGE_FILES; i++)
    {
        //evaluate_coverage_files();
        FILE *coverage_file = fopen(CODE_COVERAGE_FILES[i], "wb");
        if (coverage_file)
        {
            fclose(coverage_file);
        }
    }

    if (argc <= 1)
    {
        return 0;
    }
    if (strcmp(argv[1], "--no-inst") == 0)
    {
        blackbox_fuzzing();
    }
    else if (strcmp(argv[1], "--inst") == 0)
    {
        whitebox_fuzzing();
    }

    return 0;
}