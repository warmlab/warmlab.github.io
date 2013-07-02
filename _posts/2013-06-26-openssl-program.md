---
layout: default
title: 使用OpenSSL编程
---
OpenSSL API文档看起来挺费劲，也没有多少关于OpenSSL使用的教程

OpenSSL 是用于安全通信的最著名的开放库。它诞生于 1998 年，源自Eric Young和Tim Hudson开发的SSLeay库。 

数据在传输过程中可能被截取或窃听，明文数据一旦被截取或窃听，内容也就随之泄露，如果泄露的数据是加密的数据，数据还得经过解密。通过SSL加密的数据，理论上是比较安全的。不过，由于现代计算机速度越来越快，而且密码破译也不断进步，因此SSL中使用的加密协议被破解的可能性也在增大。

##什么是SSL

SSL是一个缩写，代表Secure Sockets Layer。是现行Internet上安全通信的标准，并且将数据密码术集成到协议之中。数据在离开计算机之前就已经被加密，然后只有到达它预定的目标后才被解密。

SSL可用于Internet上大多类型的协议，不管是HTTP、POP3，还是FTP；还可以用SSL来保护Telnet会话。尽管可以用SSL保护任何连接，但是不必对每一连接都使用SSL。在传输敏感信息，如身份信息，银行密码时，建议使用SSL。

OpenSSL不仅仅是SSL，它可以实现消息摘要、文件的加密和解密、数字证书、数字签名和随机数字。OpenSSL不只是API，它还是一个命令行工具。命令行工具可以完成与API同样的工作，而且可以测试SSL服务器和客户机。

##准备
首先需要引入必需的头文件，初始化SSL。ssl.h、bio.h和err.h。它们是openssl目录的子目录，而且都是开发所必需的。要初始化OpenSSL库，只需要三行代码。

	:::c
	/* 必需的开发头文件和步骤 */
	/* OpenSSL headers */
	#include <openssl/bio.h>
	#include <openssl/ssl.h>
	#include <openssl/err.h>
	/* Initializing OpenSSL */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
##建立非安全连接
建立连接的时候我们首先想到的是采用socket，不过现在我们将用OpenSSL的库来实现这一功能。OpenSSL使用了一个名为BIO的抽象库来处理包括文件和套接字在内的各种类型的通信。我们还可以将OpenSSL设置成为一个过滤器，比如用于UU或Base64编码的过滤器。

建立连接之前，要建立一个指向BIO对象的指针，类似于C语言中的文件流FILE指针

	:::c
	BIO *bio;
###打开连接
创建新连接调用`BIO_new_connect`函数即可，可以在同一个调用中同时指定主机名和端口号，也可以将其拆分为两个单独的调用：一个是调用创建连接并设置主机名的`BIO_new_connect()`函数，另一个是调用设置端口号的`BIO_set_conn_port`(`BIO_set_conn_int_port`)函数。

一旦BIO的主机名和端口号都已指定，该指针会尝试打开连接。如果创建BIO对象时遇到问题，指针将会是NULL。为了确保连接成功，必须调用`BIO_do_connect`函数。

	:::c
	/* 创建并打开连接 */
	/* 指定的主机名和端口创建了一个新的 BIO 对象 */
	bio = BIO_new_connect("warmlab.com:80");
	if(bio == NULL) {
		/* Handle the failure */
	}
	if(BIO_do_connect(bio) <= 0) {
		/* Handle failed connection */
	}
###与服务器通信
无论BIO对象是套接字还是文件，对其进行的读和写操作都可以通过以下两个函数来进行：`BIO_read`和`BIO_write`，这和Linux中对文件描述符和socket描述符都可以使用`read`和`write`进行操作类似。

`BIO_read`将尝试从服务器读取一定数目的字节。它返回读取的字节数、0或者-1。在受阻塞的连接中，该函数返回0，表示连接已经关闭，而-1则表示连接出现错误。在非阻塞连接的情况下，返回0表示没有可以获得的数据，返回-1表示连接出错。可以调用BIO_should_retry来确定是否可能重复出现该错误。

	:::c
	/* 从连接读取数据 */
	int x = BIO_read(bio, buf, len);
	if(x == 0) {
		/* Handle closed connection */
	} else if (x < 0) {
		if(! BIO_should_retry(bio)) {
			/* Handle failed read here */
		}
		/* Do something to handle the retry */
	}
`BIO_write`会试着将字节写入套接字。它将返回实际写入的字节数、0或者-1。同`BIO_read`，0或-1不一定表示错误。BIO_should_retry是找出问题的途径。如果需要重试写操作，它必须使用和前一次完全相同的参数。

	:::c
	/* 将数据写到连接 */
	if(BIO_write(bio, buf, len) <= 0) {
		if(! BIO_should_retry(bio)) {
			/* Handle failed write here */
		}
		/* Do something to handle the retry */
	}
###关闭连接
我们可以调用以下两个函数来关闭连接：`BIO_reset`或`BIO_free_all`。如果您还需要重新使用对象，那么调用第一个函数。如果不再重新使用它，则调用第二个函数。

`BIO_reset`关闭连接并重新设置BIO对象的内部状态，以便可以重新使用连接。如果要在整个应用程序中使用同一对象，比如使用一台安全的聊天客户机，那么这样做是有益的。该函数没有返回值。

`BIO_free_all`释放内部结构体，并释放所有相关联的内存，其中包括关闭相关联的套接字。如果将BIO嵌入于一个类中，那么应该在类的析构函数中使用这个调用。

	:::c
	/* 关闭连接 */
	/* To reuse the connection, use this line */
	BIO_reset(bio);
	/* To free it from memory, use this line */
	BIO_free_all(bio);

##建立安全连接
安全连接要求在连接建立后进行握手。在握手过程中，服务器向客户机发送一个证书， 客户端接收到证书后，根据一组可信任证书(在连接建立之前提前加载的一个可信任证书库)来核实该证书，同时检查证书，以确保它没有过期。
###设置安全连接
此时我们需要一个类型为SSL_CTX和SSL的指针。SSL_CTX指针保存了一些SSL的信息，可以通过它通过BIO建立SSL连接。结构SSL_CTX通过函数调用`SSL_CTX_new()`创建，该函数的参数一般是`SSLv23_client_method()`；SSL指针用来保持连接，同时可以用来检查连接信息或设置其他SSL参数。

	:::c
	/* 设置SSL指针 */
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	SSL *ssl;
###加载可信任证书库
在创建上述结构之后，需要加载一个可信任证书库，这是成功验证每个证书所必需的。如果不能确认证书是可信任的，那么OpenSSL会将证书标记为无效，不过连接仍可以继续。

OpenSSL附带了一组可信任证书，它们位于源文件树的certs目录中。每个证书都是一个独立的文件，需要单独加载每一个证书。在certs目录下，还有一个存放过期证书的子目录，试图加载这些证书将会出错。

使用`SSL_CTX_load_verify_locations`来加载可信任证书库文件。该函数需要三个参数：SSL_CTX指针、可信任库文件的路径，以及证书所在目录的路径。必须指定可信任库文件或证书的目录。 如果指定成功返回1，失败返回0。

	:::c
	/* 加载信任库 */
	if(! SSL_CTX_load_verify_locations(ctx, "/path/to/TrustStore.pem", NULL)) {
		/* Handle failed load here */
	}
使用目录存储可信任库时，要以特定的方式命名文件。OpenSSL文档详细的阐述了应该如何去做，另外，OpenSSL附带了一个名为`c_rehash`的工具， 它可以将文件夹配置为可用于`SSL_CTX_load_verify_locations()`的路径参数。为了指定所有需要的验证证书，可以根据需要命名任意数量的单独文件或文件夹，当然也可以同时指定文件和文件夹。

	:::shell
	# 将文件夹配置为SSL_CTX_load_verify_locations路径参数
	c_rehash /path/to/certfolder
在shell里执行了上述命令，然后

	:::c
	/* 使用上述用c_rehash配置的路径 */
	if(! SSL_CTX_load_verify_locations(ctx, NULL, "/path/to/certfolder")) {
		/* Handle error here */
	}
###创建安全连接
调用` BIO_new_ssl_connect()`创建BIO对象，参数是SSL_CTX。有时候需要SSL指针，例如使用`SSL_set_mode()`函数设置SSL。我们用该函数设置`SSL_MODE_AUTO_RETRY`标记，设置该标记后，如果服务器突然希望进行一次新的握手，那么OpenSSL可以在后台处理它。如果没有这个选项，当服务器希望进行一次新的握手时，进行读或写操作都将返回一个错误。

	:::c
	/* 设置BIO对象 */
	bio = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(bio, & ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
上述步骤完成后，就可以创建连接了。调用`BIO_set_conn_hostname`设置主机名，主机名和端口的格式和`BIO_new_connect()`一致。为了确定成功打开连接，需要调用`BIO_do_connect`函数，它将执行握手来建立安全连接。

	:::c
	/* Attempt to connect */
	BIO_set_conn_hostname(bio, "hostname:port");
	/* Verify the connection opened and perform the handshake */
	if(BIO_do_connect(bio) <= 0) {
		/* Handle failed connection */
	}
连接建立后，必须检查证书，以确定它是否有效。实际上，OpenSSL为我们完成了这项任务。如果证书有致命的问题（例如，哈希值无效），那么将无法建立连接。但是，如果证书的问题并不是致命的（当它已经过期 或者尚不合法时），那么仍可以继续使用连接。

可以将 SSL 结构作为惟一参数，调用 SSL_get_verify_result 来查 明证书是否通过了 OpenSSL 的检验。如果证书通过了包括信任检查在内的 OpenSSL 的内部检查，则返回 X509_V_OK。如果有地方出了问题，则返回一个错误代码，该代码被记录在命令行工具的 verify 选项下。

**注意：**验证失败并不意味着连接不能使用。是否应该使用连接取决于验证结果和安全方面的考虑。例如，失败的信任验证可能只是意味着没有可信任的证书。连接仍然可用，只是需要从思想上提高安全意识。

	:::c
	/* 检查证书是否有效 */
	if(SSL_get_verify_result(ssl) != X509_V_OK) {
		/* Handle the failed verification */
	}
正常连接后，与服务起的通信调用之前说过的`BIO_read`和`BIO_write`，关闭连接使用`BIO_reset`和`BIO_free_all()`

必须在结束应用程序之前的某个时刻释放 SSL_CTX，调用SSL_CTX_free来释放该结构。

	:::c
	/* 清除SSL_CTX */
	SSL_CTX_free(ctx);
##错误检测
OpenSSL在运行过程中会遇到问题时，会出现错误，捕捉这些错误，是程序员的责任。如何捕捉错误呢，OpenSSL给我们提供了函数`Err_get_error()`，该函数返回错误代码，然后通过函数`SSL_load_error_strings()`或`ERR_load_BIO_strings()`获得错误代码对应的字符串。

	* 函数描述
	* ERR_reason_error_string	返回一个描述错误的字符串
	* ERR_lib_error_string	指出错误发生在哪个库中
	* ERR_func_error_string	返回导致错误的OpenSSL函数
	* SSL_load_error_strings	返回一个描述错误的字符串
	* ERR_load_BIO_strings	返回一个描述错误的字符串
	* ERR_error_string	返回一个描述错误的字符串，该函数将错误代码和一个预分配的缓冲区作为参数。而这个缓冲区必须是 256 字节长。如果该参数为NULL，则OpenSSL会将字符串写入到一个长度为256字节的静态缓冲区中，并返回指向该缓冲区的指针。下一次调用ERR_error_string时，静态缓冲区会被覆盖。
	* ERR_print_errors	将错误信息输出到BIO指针
	* ERR_print_errors_fp	将错误信息输出到FILE文件指针

表中将错误信息输出到BIO或者FILE的格式如下：

\[pid\]:error:\[error code\]:\[library name\]:\[function name\]:\[reason string\]:\[file name\]:\[line\]:\[optional text message\]

其中，\[pid\] 是进程 ID，\[error code\] 是一个8位十六进制代码，\[file name\]是 OpenSSL库中的源代码文件，\[line\]是源文件中的行号。

	:::c
	/* 打印出最后一个错误 */
	printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
	/* 获得预先格式化的错误字符串 */
	printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
	/* 转储错误队列 */
	ERR_print_errors_fp(FILE *);
	ERR_print_errors(BIO *);

在这里介绍的仅仅是OpenSSL最基础的功能，OpenSSL还有很多需要学习。
