# CTF Service Library #

This library is intended to provide a common set of functionality for writing
CTF services. This is defined as setting up a simple forking server listening
on a port that spawns children executing a connection handler with privileges
dropped from root to some service-specific user. The primary goal is to be as
close to Kenshoto, DDTEK, and LBS's implementations from the DEFCON CTF Finals
as possible while retaining a featureset similar to that of Ghost in the
Shellcode's implementation.

This library currently explicitly supports services written in C, C++, and D.
Other languages able to interface directly with C should also work, but have
not been tested.


## Usage ##

Compiling libctf should be as easy as doing:

```
$(CC) -c ctf.c -o libctf.o
```

Linking libctf should be as easy as (assuming a service named "sample"):

```
$(CC) sample.o libctf.o -o sample
```

Typical usage of this library is to implement all service-specific
functionality in a separate location and link against a custom-compiled
libctf object on a per-service basis. This allows each service to specify
custom options (listening on IPv4 vs. IPv6, for example). As such, no Makefile
is provided.


## Configuration ##

This library supports some compile-time options in the form of DEFINEs.
Supported DEFINEs are:

```
-D_DEBUG
    Removes dropping privileges so it may be run as any user.
    Removes alarm so debugging isn't timed.
    Adds a number of helpful debug messages for troubleshooting purposes.

-D_IPV6
    Switches socket from IPV4 to IPV6.

-D_CHROOT
    Additionally chroots into the service user's directory.

-D_NORAND
    Skips randomizing the socket descriptor.
```


## API ##

This library provides the following standard functions as its API:

```
int ctf_listen(const unsigned short port, const int proto)
    Binds the service to a port and begins listening.

void ctf_server(int sd, const char *user, int (*handler)(int))
    Accepts connections and forks off child processes to handle them.

void ctf_privdrop(const char *user)
    Drops privileges to chosen user.

int ctf_randfd(int old)
    Randomizes a file/socket descriptor.

int ctf_recv(int sd, char *msg, unsigned int len)
    Receives message of chosen length and returns number of bytes received.

int ctf_recvuntil(int sd, char *msg, unsigned int len, const char stop)
    Receives until chosen length or sentinel and returns number of bytes received.

int ctf_send(int sd, const char *msg, unsigned int len)
    Sends a message of chosen length and returns number of bytes sent.

int ctf_sendf(int sd, const char *msg, ...)
    Sends a formatted message and returns number of bytes sent.
```


## Examples ##

An example sample.c implementing a basic CTF service using this library
would look something like the following:

```
#include "ctf.h"

const char *USER = "sample";            // user to drop privileges to
const unsigned short PORT = 65535;      // port to bind and listen on

int child_main(int sd)                  // handler for incoming connections
{
    char buf[32];
    int len;
    if ((len = ctf_recvuntil(sd, buf, 256, '\n')) > 0) {
        buf[len] = '\0';
        ctf_send(sd, buf, strlen(buf));
    }
    return 0;
}

int main(int argc, char **argv)         // main function
{
    (void)argc;
    (void)argv;
    int sd;  // socket descriptor
    sd = ctf_listen(PORT, IPPROTO_TCP);
    ctf_server(sd, USER, child_main);
    return 0;
}
```

If you're using xinetd or socat instead of binding and listening on a port
yourself, the example would instead look something like:

```
#include "ctf.h"

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char buf[32];
    int len;
    setvbuf(stdout, NULL, _IONBF, 0);
    if ((len = ctf_recvuntil(fileno(stdin), buf, 256, '\n')) > 0) {
        buf[len] = '\0';
        ctf_send(fileno(stdout), buf, strlen(buf));
    }
    return 0;
}
```

With xinetd, however, you will need to add a line in /etc/services and a
configuration file in /etc/xinetd.d that looks like something like this:

```
service sample
{
    disable     = no
    id          = sample
    socket_type = stream
    protocol    = tcp
    wait        = no
    user        = sample
    server      = /home/sample/sample
}
```


## Roadmap ##

The following is a list of features that have yet to be added and/or tested:

* Building on OSX gives warnings on certain network-related things
* Haven't actually built on FreeBSD yet
* Haven't compiled to any architectures other than x86/x86-64
* Haven't fully tested SCTP and RAW codepaths
* Haven't fully tested C++ and D bindings (can't get gdc to link properly)
* Should probably create bindings to other languages (C#, Java, Ruby)
* Currently no support whatsoever for Windows services (in Wine or otherwise)
* Haven't yet implemented DDTEK's backdoor stuff from DEFCON CTF Finals 19 and 20
