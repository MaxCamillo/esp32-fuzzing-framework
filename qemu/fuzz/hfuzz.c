#include <stdio.h>

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "fuzz/hfuzz.h"



#define BUFFER_SIZE 0x500

//#define BLACKBOX_FUZZING 1



/**
 * Point at which the memory and register dump should be loaded
*/
target_ulong hfuzz_qemu_setup_point = 0x40000450; 

/**
 * Point, where the memory dump was taken
 */
target_ulong hfuzz_qemu_entry_point = 0; 


#define MAX_EXIT_POINTS 10
/**
 * Points where to exit the execution if child flag is set
 */ 
target_ulong hfuzz_qemu_exit_points[MAX_EXIT_POINTS];

size_t hfuzz_qemu_n_exit_points = 0;

char * hfuzz_dump_file = 0;
char * hfuzz_regs_file = 0;

//http request ending
const char *http_crlf = " HTTP/1.1\r\nHost: 123.0.0.1\r\n\r\n";
//const char *http_crlf = "\x20\r\n";

extern void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);
extern void hfuzzInstrumentInit(void);

//Whitebox fuzzing
#ifndef BLACKBOX_FUZZING

#define TARGET_ADDRESS "localhost"
#define TARGET_PORT 8081

/**
 * send data to target, check liveness
 * */
void sendOneRequest(const uint8_t *fuzz_string, size_t fuzz_len);
void sendOneRequest(const uint8_t *fuzz_string, size_t fuzz_len)
{

    //socket to target
    int target_sockfd;
    struct sockaddr_in target_sock_addr;
    struct hostent *hp;

    //Send and receive buffer
    char buf[BUFFER_SIZE]; //TODO Determine buffer size

    if (fuzz_len > BUFFER_SIZE - strlen(http_crlf))
    {
        printf("Fuzzer data too big!! \n");
        return;
    }

    //concatenate fuzzer string + http header and save to buf
    snprintf(buf, sizeof buf, "%s%s", fuzz_string, http_crlf);
    //memcpy(buf, fuzz_string, fuzz_len * sizeof(uint8_t));
    //memcpy(buf + fuzz_len * sizeof(uint8_t), http_crlf, (strlen(http_crlf) + 1) * sizeof(char));

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
    int len = send(target_sockfd, buf, strlen(buf) + 1, 0);
    //printf("%i \n", sent);

    if(len < 0) {
      raise(SIGSEGV); //probably fault
    }

    pthread_yield();
    //Read response to avoid full buffers of target

    read(target_sockfd, buf, BUFFER_SIZE);


    close(target_sockfd);
}

static void fork_server(CPUState *cpu) {

  pid_t pid = fork();
  if (pid < 0) {
    fputs("fork error\n", stderr);
    exit(1);
  }

  // Child
  if (!pid) {

    const uint8_t *fuzz_string = (uint8_t *)"";
    size_t fuzz_len = 0;

    
    hfuzzInstrumentInit();

    //wait for target to come up
    sleep(4);

    // //get fuzzing string from honggfuzz
    while (2) {
      HonggfuzzFetchData(&fuzz_string, &fuzz_len);
      sendOneRequest(fuzz_string, fuzz_len);
    }
    exit(1);
  } else {
    // Parent
    return;
  }

}
#endif //WHITEBOX_FUZZING


#ifdef BLACKBOX_FUZZING

#ifdef BLACKBOX_FUZZING
#define DATA_POINT 0x3ffba4ca
#define LENGTH_REGISTER 8

#define USE_FORKSERVER 1
#endif
/**
 * Checks if request in guest buffer is a GET request
 */
bool isGetRequest(CPUState *cpu);
bool isGetRequest(CPUState *cpu) {
  uint8_t a[10];
  uint64_t uri_pointer = DATA_POINT;
  address_space_read(cpu->as, uri_pointer, MEMTXATTRS_UNSPECIFIED, a,10 );
  if(strncmp((char*)a, "qqq", 3) == 0) {
    return true;
  }
    return false;
}

/**
 * Fetches fuzzing data and writes it to guest buffer
 */
void injectFuzzingData(CPUState *cpu);
void injectFuzzingData(CPUState *cpu) {
  
  //const uint8_t *fuzz_string = (uint8_t *)"\x00\x00\x00\x01\x31\x31\x31\x31\x31\x31\xef\xbf\xbd\x31\x31\x31\x31\x31\x31\x31\x31\x31";
  const uint8_t *fuzz_string = (uint8_t *)"\x31\xef\xbf\xbd\x59\xef\xbf\xbd\x67\xef\xbf\xbd\x37\x32\x36\x33\x32\x32\x32\x37\x30\x33\x32\x39\x1c\xef\xbf\xbd\x33\xef\xbf\xbd\x74\xc6\x9a\xef\xbf\xbd\x4e\x3e\xef\xbf\xbd\xdf\x96\x76\x24\x6b\x39\x59\x1d\xef\xbf\xbd\xef\xbf\xbd\x29\xef\xbf\xbd\xef\xbf\xbd\x3f\x03\xd3\x9c\x04\xef\xbf\xbd\x48\x5c\x0a\xd9\x97\x1a\x7d\x5a\xef\xbf\xbd\xef\xbf\xbd\x47\x4d\x57\x3b\x3c\x41\xef\xbf\xbd\xef\xbf\xbd\x71\x4b\xef\xbf\xbd\xef\xbf\xbd\x4e\xef\xbf\xbd\xef\xbf\xbd\x7c\xef\xbf\xbd\x23\xef\xbf\xbd\x3d\x4b\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x23\x33\xef\xbf\xbd\x68\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x58\x6f\x07\xef\xbf\xbd\x47\xda\xa6\xc6\x8c\xef\xbf\xbd\xef\xbf\xbd\x32\xef\xbf\xbd\xdd\xbf\x5c\xef\xbf\xbd\x75\x06\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x58\x6f\x07\xef\xbf\xbd\x47\xda\xa6\xc6\x8c\xef\xbf\xbd\xef\xbf\xbd\x32\xef\xbf\xbd\xdd\xbf\xef\xbf\xbd\x2b\xca\x87\x56\x3c\x17\x45\xef\xbf\xbd\x0a\x0a\xef\xbf\xbd\xef\xbf\xbd\x14\x26\x62\xef\xbf\xbd\xef\xbf\xbd\x18\xef\xbf\xbd\xef\xbf\xbd\x47\x72\xef\xbf\xbd\x3c\x56\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x27\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xd3\xac\xef\xbf\xbd\xef\xbf\xbd\x42\xef\xbf\xbd\x38\x13\x02\x05\xef\xbf\xbd\xef\xbf\xbd\x46\x42\x15\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x26\x48\x54\x54\x50\x2f\x31\x2e\x43\xef\xbf\xbd\xef\xbf\xbd\x33\x35\x30\x39\x37\x32\x36\x33\x32\x32\x32\x37\x30\x33\x32\x39\x1c\xef\xbf\xbd\x33\xef\xbf\xbd\x74\xc6\x9a\xef\xbf\xbd\x4e\x3e\xef\xbf\xbd\xdf\x96\x76\x24\x6b\x39\x59\x1d\xef\xbf\xbd\xef\xbf\xbd\x29\xef\xbf\xbd\xef\xbf\xbd\x3f\x03\xd3\x9c\x04\xef\xbf\xbd\x48\x5c\x0a\xd9\x97\x1a\x7d\x5a\xef\xbf\xbd\xef\xbf\xbd\x47\x4d\x57\x3b\x3c\x41\xef\xbf\xbd\xef\xbf\xbd\x71\x4b\xef\xbf\xbd\xef\xbf\xbd\x4e\xef\xbf\xbd\xef\xbf\xbd\x7c\xef\xbf\xbd\x23\xef\xbf\xbd\x3d\x38\x33\x34\x33\x37\x36\x30\x32\x36\x30\x35\x31\x35\x35\x37\x38\x33\x36\x34\xef\xbf\xbd\xc6\x8c\xef\xbf\xbd\xef\xbf\xbd\x32\xef\xbf\xbd\xdd\xbf\x5c\xef\xbf\xbd\x75\x06\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x58\x6f\x07\xef\xbf\xbd\x47\xda\xa6\xc6\x8c\xef\xbf\xbd\xef\xbf\xbd\x32\xef\xbf\xbd\xdd\xbf\xef\xbf\xbd\x2b\xca\x87\x56\x3c\x17\x45\xef\xbf\xbd\x0a\x0a\xef\xbf\xbd\xef\xbf\xbd\x14\x26\x62\xef\xbf\xbd\xef\xbf\xbd\x18\xef\xbf\xbd\xef\xbf\xbd\x47\x72\xef\xbf\xbd\x3c\x56\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x27\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\xd3\xac\xef\xbf\xbd\xef\xbf\xbd\x42\xef\xbf\xbd\x38\x13\x02\x05\xef\xbf\xbd\xef\xbf\xbd\x46\x42\x79\x41\xd2\x8e\xef\xbf\xbd\xef\xbf\xbd\x0b\x4c\xef\xbf\xbd\xef\xbf\xbd\x3c\xef\xbf\xbd\x30\x29\x53\xef\xbf\xbd\x5c\x55\x2d\x38\x30\x35\x32\x31\x31\x32\x33\x31\x38\x39\x37\x36\x34\x39\x37\x31\x35\x38\xef\xbf\xbd\xef\xbf\xbd\x78\xef\xbf\xbd\x00";
  //const uint8_t *fuzz_string = (uint8_t *)"GET /hello";
  size_t fuzz_len = 440; //strlen((char*)fuzz_string) ;

  HonggfuzzFetchData(&fuzz_string, &fuzz_len);

  char buf[BUFFER_SIZE];

  if (fuzz_len > BUFFER_SIZE - strlen(http_crlf) + 1)
  {
      printf("Fuzzer data too big!! \n");
      fuzz_len = BUFFER_SIZE - strlen(http_crlf) + 1;
  }

  //concatenate fuzzer string + http header and save to buf
  //use snprintf to avoid null bytes in string which would lead to timeouts
  snprintf(buf, sizeof buf, "%s%s", fuzz_string, http_crlf);
  //memcpy(buf, fuzz_string, fuzz_len * sizeof(uint8_t));
  //memcpy(buf + fuzz_len * sizeof(uint8_t), http_crlf, (strlen(http_crlf) +1) * sizeof(char));

  uint32_t data_len = strlen(buf);//fuzz_len * sizeof(uint8_t); // + (strlen(http_crlf) +1) * sizeof(char);

  uint64_t uri_pointer = DATA_POINT; //((CPUArchState *) cpu->env_ptr)->regs[2] + 0x280;

  address_space_rw(cpu->as, uri_pointer, MEMTXATTRS_UNSPECIFIED, (uint8_t *)buf, data_len, true);


  //address_space_rw(cpu->as, 0x3FFE5400, MEMTXATTRS_UNSPECIFIED, (uint8_t *)&data_len, sizeof(uint32_t), true);

  ((CPUArchState *) cpu->env_ptr)->regs[LENGTH_REGISTER] = data_len;

  
  printf("%s %d\n", (char*)buf, data_len);

      
}


uint32_t nonForkPasses = 0;

static void fork_server(CPUState *cpu) {

  //skip if request is not a get request
  // if(!isGetRequest(cpu))  {
  //   return;
  // }

  hfuzzInstrumentInit();


  //Skip first execution to profit from cache ;)
  //Maybe we can run the complete initial corpus from hfuzz to profit even more from cache?
  if(nonForkPasses > 0 || !USE_FORKSERVER) {
    //We need to use fuzzing data (Or hfuzz won't recognize parts hit by original input)
    injectFuzzingData(cpu);
    nonForkPasses --;
    return;
  } 


  while (2) {
    
    pid_t pid = fork(); //syscall(SYS_clone, CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_IO | CLONE_PARENT, 0); //CLONE_PTRACE
    if (pid < 0) {
      fputs("fork error\n", stderr);
      exit(1);
    }

    // Parent
    if (pid) {


      int status;
      if (waitpid(pid, &status, 0) <= 0) {
        fputs("waitpid error\n", stderr);
        exit(1);
      }
      if(status == 1 ) {
        raise(SIGSEGV);
      }
      
    } else {
      // Child
      childProcess = true;
      injectFuzzingData(cpu);
      return;
    }
  }
}

#endif //BLACKBOX_FUZZING




void hfuzz_qemu_setup(CPUState *cpu) {


#ifdef HFUZZ_FORKSERVER
  fork_server(cpu);
#endif // HFUZZ_FORKSERVER
}

extern void hfuzz_trace_cmp4(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);
extern void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);

void HELPER(hfuzz_qemu_trace_cmp_i64)(
        uint64_t cur_loc, uint64_t arg1, uint64_t arg2
    ) {
  hfuzz_trace_cmp8(cur_loc, arg1, arg2);
}

void HELPER(hfuzz_qemu_trace_cmp_i32)(
        uint32_t cur_loc, uint32_t arg1, uint32_t arg2
    ) {
  hfuzz_trace_cmp4(cur_loc, arg1, arg2);
}

QemuOptsList qemu_fuzz_opts = {
    .name = "fuzz",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_fuzz_opts.head),
    .desc = {
        {
            .name = "setup",
            .type = QEMU_OPT_STRING,
        },{
            .name = "entry",
            .type = QEMU_OPT_STRING,
        },{
            .name = "exit",
            .type = QEMU_OPT_STRING,
        },{
            .name = "dump_file",
            .type = QEMU_OPT_STRING,
        },{
            .name = "regs_file",
            .type = QEMU_OPT_STRING,
        },
        { /* end of list */ }
    },
};

int qemu_fuzz_option(const char *str)
{
    char setup[64], entry[64], exit[64], dumpfile[256];
    QemuOpts *opts;
    int rc, offset;

    rc = sscanf(str, "%63[^.=].%63[^=].%63[^=].%63[^=]%n", setup, entry, exit, dumpfile, &offset);
    if (rc == 2 && str[offset] == '=') {
        opts = qemu_opts_create(&qemu_fuzz_opts, NULL, 0, &error_abort);
        qemu_opt_set(opts, "setup", setup, &error_abort);
        qemu_opt_set(opts, "entry", entry, &error_abort);
        qemu_opt_set(opts, "exit", exit, &error_abort);
        qemu_opt_set(opts, "dump_file", dumpfile, &error_abort);
        qemu_opt_set(opts, "regs_file", str + offset + 1, &error_abort);
        return 0;
    }

    opts = qemu_opts_parse_noisily(&qemu_fuzz_opts, str, false);
    if (!opts) {
        return -1;
    }

    const char * opt_setup = qemu_opt_get(opts, "setup");
    hfuzz_qemu_setup_point = strtol(opt_setup, 0, 0);

    const char * opt_entry = qemu_opt_get(opts, "entry");
    hfuzz_qemu_entry_point = strtol(opt_entry, 0, 0);

    char * opt_exit = (char *) qemu_opt_get(opts, "exit");

    opt_exit = strtok(opt_exit, "+");
    int i;
    for (i = 0; i < MAX_EXIT_POINTS && opt_exit != NULL; i++) {
      hfuzz_qemu_exit_points[i] = strtol(opt_exit, 0, 0);
      opt_exit = strtok(NULL, "+");
    }

    hfuzz_qemu_n_exit_points = i;

    hfuzz_dump_file = (char *) qemu_opt_get(opts, "dump_file");

    hfuzz_regs_file = (char *) qemu_opt_get(opts, "regs_file");

    return 0;
}


