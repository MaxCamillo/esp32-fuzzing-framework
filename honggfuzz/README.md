# Description

A security oriented, feedback-driven, evolutionary, easy-to-use fuzzer with interesting analysis options. See the [Usage document](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md) for a primer on Honggfuzz use.

# Code

  * Latest stable version: [2.0](https://github.com/google/honggfuzz/releases)
  * [Changelog](https://github.com/google/honggfuzz/blob/master/CHANGELOG)

# Features

  * It's __multi-process__ and __multi-threaded__: there's no need to run multiple copies of your fuzzer, as honggfuzz can unlock potential of all your available CPU cores with a single running instance. The file corpus is automatically shared and improved between all fuzzed processes.
  * It's blazingly fast when the [persistent fuzzing mode](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md)) is used. A simple/empty _LLVMFuzzerTestOneInput_ function can be tested with __up to 1mo iterations per second__ on a relatively modern CPU (e.g. i7-6700K).
  * Has a [solid track record](#trophies) of uncovered security bugs: the __only__ (to the date) __vulnerability in OpenSSL with the [critical](https://www.openssl.org/news/secadv/20160926.txt) score mark__ was discovered by honggfuzz. See the [Trophies](#trophies) paragraph for the summary of findings to the date.
  * Uses low-level interfaces to monitor processes (e.g. _ptrace_ under Linux and NetBSD). As opposed to other fuzzers, it __will discover and report hijacked/ignored signals from crashes__ (intercepted and potentially hidden by a fuzzed program).
  * Easy-to-use, feed it a simple corpus directory (can even be empty for the [feedback-driven fuzzing](https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md)), and it will work its way up, expanding it by utilizing feedback-based coverage metrics.
  * Supports several (more than any other coverage-based feedback-driven fuzzer) hardware-based (CPU: branch/instruction counting, __Intel BTS__, __Intel PT__) and software-based [feedback-driven fuzzing](https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md) modes. Also, see the new __[qemu mode](https://github.com/google/honggfuzz/tree/master/qemu_mode)__ for blackbox binary fuzzing.
  * Works (at least) under GNU/Linux, FreeBSD, NetBSD, Mac OS X, Windows/CygWin and [Android](https://github.com/google/honggfuzz/blob/master/docs/Android.md).
  * Supports the __persistent fuzzing mode__ (long-lived process calling a fuzzed API repeatedly). More on that can be found [here](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md).
  * It comes with the __[examples](https://github.com/google/honggfuzz/tree/master/examples) directory__, consisting of real world fuzz setups for widely-used software (e.g. Apache HTTPS, OpenSSL, libjpeg etc.).
  * Provides a __[corpus minimization](https://github.com/google/honggfuzz/blob/master/docs/USAGE.md#corpus-minimization--m)__ mode.

---

<p align="center">
 <img src="https://raw.githubusercontent.com/google/honggfuzz/master/screenshot-honggfuzz-1.png" width="75%" height="75%">
</p>

---

# Requirements

  * **Linux** - The BFD library (libbfd-dev) and libunwind (libunwind-dev/libunwind8-dev), clang-5.0 or higher for software-based coverage modes
  * **FreeBSD** - gmake, clang-5.0 or newer
  * **NetBSD** - gmake, clang, capstone, libBlocksRuntime
  * **Android** - Android SDK/NDK. Also see [this detailed doc](https://github.com/google/honggfuzz/blob/master/docs/Android.md) on how to build and run it
  * **Windows** - CygWin
  * **Darwin/OS X** - Xcode 10.8+
  * if **Clang/LLVM** is used to compile honggfuzz - link it with the BlocksRuntime Library (libblocksruntime-dev)

# Trophies

Honggfuzz has been used to find a few interesting security problems in major software packages; An incomplete list:


  * [Pre-auth remote crash in __OpenSSH__](https://anongit.mindrot.org/openssh.git/commit/?id=28652bca29046f62c7045e933e6b931de1d16737)
  * __Apache HTTPD__
    * [Remote crash in __mod\_http2__ • CVE-2017-7659](http://seclists.org/oss-sec/2017/q2/504)
    * [Use-after-free in __mod\_http2__ • CVE-2017-9789](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9789)
    * [Memory leak in __mod\_auth\_digest__ • CVE-2017-9788](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-9788)
    * [Out of bound access • CVE-2018-1301](http://seclists.org/oss-sec/2018/q1/265)
    * [Write after free in HTTP/2 • CVE-2018-1302](http://seclists.org/oss-sec/2018/q1/268)
    * [Out of bound read • CVE-2018-1303](http://seclists.org/oss-sec/2018/q1/266)
  * Various __SSL__ libs
    * [Remote OOB read in __OpenSSL__ • CVE-2015-1789]( https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1789)
    * [Remote Use-after-Free (potential RCE, rated as __critical__) in __OpenSSL__ • CVE-2016-6309](https://www.openssl.org/news/secadv/20160926.txt)
    * [Remote OOB write in __OpenSSL__ • CVE-2016-7054](https://www.openssl.org/news/secadv/20161110.txt)
    * [Remote OOB read in __OpenSSL__ • CVE-2017-3731](https://www.openssl.org/news/secadv/20170126.txt)
    * [Uninitialized mem use in __OpenSSL__](https://github.com/openssl/openssl/commit/bd5d27c1c6d3f83464ddf5124f18a2cac2cbb37f)
    * [Crash in __LibreSSL__](https://github.com/openbsd/src/commit/c80d04452814d5b0e397817ce4ed34edb4eb520d)
    * [Invalid free in __LibreSSL__](https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.6.2-relnotes.txt)
    * [Uninitialized mem use in __BoringSSL__](https://github.com/boringssl/boringssl/commit/7dccc71e08105b100c3acd56fa5f6fc1ba9b71d3)
  * [Adobe __Flash__ memory corruption • CVE-2015-0316](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0316)
  * [Multiple bugs in the __libtiff__ library](http://bugzilla.maptools.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert@swiecki.net;product=libtiff;emailtype1=substring)
  * [Multiple bugs in the __librsvg__ library](https://bugzilla.gnome.org/buglist.cgi?query_format=advanced;emailreporter1=1;email1=robert%40swiecki.net;product=librsvg;emailtype1=substring)
  * [Multiple bugs in the __poppler__ library](http://lists.freedesktop.org/archives/poppler/2010-November/006726.html)
  * [Multiple exploitable bugs in __IDA-Pro__](https://www.hex-rays.com/bugbounty.shtml)
  * [Remote DoS in __Crypto++__ • CVE-2016-9939](http://www.openwall.com/lists/oss-security/2016/12/12/7)
  * Programming language interpreters
    * [__PHP/Python/Ruby__](https://github.com/dyjakan/interpreter-bugs)
    * [PHP WDDX](https://bugs.php.net/bug.php?id=74145)
    * [PHP](https://bugs.php.net/bug.php?id=74194)
    * Perl: [#1](https://www.nntp.perl.org/group/perl.perl5.porters/2018/03/msg250072.html), [#2](https://github.com/Perl/perl5/issues/16468), [#3](https://github.com/Perl/perl5/issues/16015)
  * [Double-free in __LibXMP__](https://github.com/cmatsuoka/libxmp/commit/bd1eb5cfcd802820073504c234c3f735e96c3355)
  * [Heap buffer overflow in SAPCAR • CVE-2017-8852](https://www.coresecurity.com/blog/sapcar-heap-buffer-overflow-crash-exploit)
  * [Crashes in __libbass__](http://seclists.org/oss-sec/2017/q4/185)
  * __FreeType 2__:
    * [CVE-2010-2497](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2497)
    * [CVE-2010-2498](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2498)
    * [CVE-2010-2499](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2499)
    * [CVE-2010-2500](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2500)
    * [CVE-2010-2519](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2519)
    * [CVE-2010-2520](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2520)
    * [CVE-2010-2527](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2010-2527)
  * Stack corruption issues in the Windows OpenType parser: [#1](https://github.com/xinali/AfdkoFuzz/blob/4eadcb19eacb2fb73e4b0f0b34f382a9331bb3b4/CrashesAnalysis/CrashesAnalysis_3/README.md), [#2](https://github.com/xinali/AfdkoFuzz/blob/master/CVE-2019-1117/README.md), [#3](https://github.com/xinali/AfdkoFuzz/tree/f6d6562dd19403cc5a1f8cef603ee69425b68b20/CVE-2019-1118)
  * [Infinite loop in __NGINX Unit__](https://github.com/nginx/unit/commit/477e8177b70acb694759e62d830b8a311a736324)
  * A couple of problems in the [__MATLAB MAT File I/O Library__](https://sourceforge.net/projects/matio): [#1](https://github.com/tbeu/matio/commit/406438f497931f45fb3edf6de17d3a59a922c257), [#2](https://github.com/tbeu/matio/commit/406438f497931f45fb3edf6de17d3a59a922c257), [#3](https://github.com/tbeu/matio/commit/a55b9c2c01582b712d5a643699a13b5c41687db1), [#4](https://github.com/tbeu/matio/commit/3e6283f37652e29e457ab9467f7738a562594b6b), [#5](https://github.com/tbeu/matio/commit/783ee496a6914df68e77e6019054ad91e8ed6420)
  * __Samba__ [tdbdump + tdbtool](http://seclists.org/oss-sec/2018/q2/206), [#2](https://github.com/samba-team/samba/commit/183da1f9fda6f58cdff5cefad133a86462d5942a), [#3](https://github.com/samba-team/samba/commit/33e9021cbee4c17ee2f11d02b99902a742d77293), [#4](https://github.com/samba-team/samba/commit/ac1be895d2501dc79dcff2c1e03549fe5b5a930c), [#5](https://github.com/samba-team/samba/commit/b1eda993b658590ebb0a8225e448ce399946ed83), [#6](https://github.com/samba-team/samba/commit/f7f92803f600f8d302cdbb668c42ca8b186a797f)
  * [Crash in __djvulibre__](https://github.com/barak/djvulibre/commit/89d71b01d606e57ecec2c2930c145bb20ba5bbe3)
  * [Multiple crashes in __VLC__](https://www.pentestpartners.com/security-blog/double-free-rce-in-vlc-a-honggfuzz-how-to/)
  * [Buffer overflow in __ClassiCube__](https://github.com/UnknownShadow200/ClassiCube/issues/591)
  * [Heap buffer-overflow (or UAF) in __MPV__](https://github.com/mpv-player/mpv/issues/6808)
  * [Heap buffer-overflow in __picoc__](https://gitlab.com/zsaleeba/picoc/issues/44)
  * Crashes in __OpenCOBOL__: [#1](https://sourceforge.net/p/open-cobol/bugs/586/), [#2](https://sourceforge.net/p/open-cobol/bugs/587/)
  * DoS in __ProFTPD__: [#1](https://twitter.com/SecReLabs/status/1186548245553483783), [#2](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-18217)
  * [Memory corruption in __htmldoc__](https://github.com/michaelrsweet/htmldoc/issues/370)
  * [Memory corruption in __OpenDetex__](https://github.com/pkubowicz/opendetex/issues/60)
  * [Memory corruption in __Yabasic__](https://github.com/marcIhm/yabasic/issues/36)
  * [Memory corruption in __Xfig__](https://sourceforge.net/p/mcj/tickets/67/)
  * __Rust__:
    * panic() in regex [#1](https://github.com/rust-lang/regex/issues/464), [#2](https://github.com/rust-lang/regex/issues/465), [#3](https://github.com/rust-lang/regex/issues/465#issuecomment-381412816)
    * panic() in h2 [#1](https://github.com/carllerche/h2/pull/260), [#2](https://github.com/carllerche/h2/pull/261), [#3](https://github.com/carllerche/h2/pull/262)
    * panic() in sleep-parser [#1](https://github.com/datrs/sleep-parser/issues/3)
    * panic() in lewton [#1](https://github.com/RustAudio/lewton/issues/27)
    * panic()/DoS in Ethereum-Parity [#1](https://srlabs.de/bites/ethereum_dos/)
    * crash() in Parts - a GPT partition manager [#1](https://github.com/DianaNites/parts/commit/d8ab05d48d87814f362e94f01c93d9eeb4f4abf4)
    * crashes in rust-bitcoin/rust-lightning [#1](https://github.com/rust-bitcoin/rust-lightning/commit/a9aa3c37fe182dd266e0faebc788e0c9ee724783)
  * ... and more

# Projects utilizing or inspired-by Honggfuzz

  * [__QuickFuzz__ by CIFASIS](http://quickfuzz.org)
  * [__OSS-Fuzz__](https://github.com/google/oss-fuzz)
  * [__Frog And Fuzz__](https://github.com/warsang/FrogAndFuzz/tree/develop)
  * [__interpreters fuzzing__: by dyjakan](https://github.com/dyjakan/interpreter-bugs)
  * [__riufuzz__: honggfuzz with AFL-like UI](https://github.com/riusksk/riufuzz)
  * [__h2fuzz__: fuzzing Apache's HTTP/2 implementation](https://github.com/icing/h2fuzz)
  * [__honggfuzz-dharma__: honggfuzz with dharma grammar fuzzer](https://github.com/Sbouber/honggfuzz-dharma)
  * [__Owl__: a system for finding concurrency attacks](https://github.com/hku-systems/owl)
  * [__honggfuzz-docker-apps__](https://github.com/skysider/honggfuzz_docker_apps)
  * [__FFW__: Fuzzing For Worms](https://github.com/dobin/ffw)
  * [__honggfuzz-rs__: fuzzing Rust with Honggfuzz](https://docs.rs/honggfuzz/)
  * [__roughenough-fuzz__](https://github.com/int08h/roughenough-fuzz)
  * [__Monkey__: a HTTP server](https://github.com/monkey/monkey/blob/master/FUZZ.md)
  * [__Killerbeez API__: a modular fuzzing framework](https://github.com/grimm-co/killerbeez)
  * [__FuzzM__: a gray box model-based fuzzing framework](https://github.com/collins-research/FuzzM)
  * [__FuzzOS__: by Mozilla Security](https://github.com/MozillaSecurity/fuzzos)
  * [__Android__: by OHA](https://android.googlesource.com/platform/external/honggfuzz)
  * [__QDBI__: by Quarkslab](https://project.inria.fr/FranceJapanICST/files/2019/04/19-Kyoto-Fuzzing_Binaries_using_Dynamic_Instrumentation.pdf)
  * [__fuzzer-test-suite__: by Google](https://github.com/google/fuzzer-test-suite)
  * [__DeepState__: by Trail-of-Bits](https://github.com/trailofbits/deepstate)
  * [__Quiche-HTTP/3__: by Cloudflare](https://github.com/cloudflare/quiche/pull/179)
  * [__Bolero__: fuzz and property testing framework](https://github.com/camshaft/bolero)
  * [__pwnmachine__: a vagrantfile for exploit development on Linux](https://github.com/kapaw/pwnmachine/commit/9cbfc6f1f9547ed2d2a5d296f6d6cd8fac0bb7e1)
  * [__Quick700__: analyzing effectiveness of fuzzers on web browsers and web servers](https://github.com/Quick700/Quick700)
  * [__python-fuzz__: gluing honggfuzz and python3](https://github.com/thebabush/python-hfuzz)
  * [__Magma__: a ground-truth fuzzing benchmark](https://github.com/HexHive/magma)
  * [__arbitrary-model-tests__: a procedural macro for testing stateful models](https://github.com/jakubadamw/arbitrary-model-tests)
  * [__Clusterfuzz__: the fuzzing engine behind OSS-fuzz/Chrome-fuzzing](https://github.com/google/clusterfuzz/issues/1128)
  * [__Apache HTTP Server__](https://github.com/apache/httpd/commit/d7328a07d7d293deb5ce62a60c2ce6029104ebad)
  * [__centos-fuzz__](https://github.com/truelq/centos-fuzz)
  * [__FLUFFI__: Fully Localized Utility For Fuzzing Instantaneously by Siemens](https://github.com/siemens/fluffi)
  * [__Fluent Bit__: a fast log processor and forwarder for Linux](https://github.com/fluent/fluent-bit/search?q=honggfuzz&unscoped_q=honggfuzz)
  * [__Samba__: a SMB server](https://github.com/samba-team/samba/blob/2a90202052558c945e02675d1331e65aeb15f9fa/lib/fuzzing/README.md)
  * [__universal-fuzzing-docker__: by nnamon](https://github.com/nnamon/universal-fuzzing-docker)
  * [__Canokey Core__: core implementations of an open-source secure key](https://github.com/canokeys/canokey-core/search?q=honggfuzz&unscoped_q=honggfuzz)
  * [__uberfuzz2__: a cooperative fuzzing framework](https://github.com/acidghost/uberfuzz2)
  * [__TiKV__: a distributed transactional key-value database](https://github.com/tikv/tikv/tree/99a922564face31bdb59b5b38962339f79e0015c/fuzz)
  * [__fuzz-monitor__](https://github.com/acidghost/fuzz-monitor/search?q=honggfuzz&unscoped_q=honggfuzz)
  * [__libmutator__: a C library intended to generate random test cases by mutating legitimate test cases](https://github.com/denandz/libmutator)
  * [__StatZone__: a DNS zone file analyzer](https://github.com/fcambus/statzone)
  * [__shub-fuzz/honggfuzz__: singularity image for honggfuzz](https://github.com/shub-fuzz/honggfuzz)
  * [__Code Intelligence__: fuzzing-as-a-service](https://www.code-intelligence.com/technology.html)
  * [__Rust's fuzztest__](https://docs.rs/crate/fuzztest)
    * [_and multiple Rust projecs_](https://github.com/search?q=%22extern+crate+honggfuzz%22&type=Code)

# Contact

  * User mailing list: [honggfuzz@googlegroups.com](mailto:honggfuzz@googlegroups.com), sign up with [this link](https://groups.google.com/forum/#!forum/honggfuzz).

__This is NOT an official Google product__
