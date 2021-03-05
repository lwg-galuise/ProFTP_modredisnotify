# Longwood Gardens ProFTPD REST Notify Module (mod_restnotify.c)

A module for the ProFTP daemon that will monitor all files uploaded
during an FTP / SFTP session and notify a REST endpoint of any uploaded
files.  The module keeps track of any renaming of files that are
uploaded.  For example the popular WinSCP secure copy or SFTP client
will upload a file with ".filepart" appended to its name.  After
successfully uploading the file WinSCP then renames the file to remove
the appended ".filepart" designation.  This module captures this event
and will report the true filename to the subscribed endpoint.

To build this module issue the following commands on any Linux machine
with ProFTPD installed:

```sh
sudo prxs -c -d -i -I /usr/include/hiredis -L /usr/lib/x86_64-linux-gnu/ mod_restnotify.c
```

**NOTE:** The above command assumes the version 0.14 libhiredis.so
installed by the packages in Debian 10.


Then the following section will need to be added to the ProFTPD
/etc/proftpd/modules.conf file (to load the module):

```
LoadModule mod_restnotify.c
```

Finally, the following configuration block will need to be added to
either the /etc/proftpd/proftpd.conf file or to one of the
/etc/proftpd/conf.d/ files (below is an example config):

**A TCP-based connection**
```
<IfModule mod_restnotify.c>
        RedisHost 127.0.0.1
        RedisPort 16379
        RedisAuth "PASSWORD GOES HERE"
        RedisStreamMaxSize 100
        NotifyStreamName sftp.longwood:notify
</IfModule mod_restnotify.c>
```

**A UNIX Domain Socket-based connection**
```
<IfModule mod_restnotify.c>
        RedisUnixSocket /var/run/redis/redis-server.sock
        RedisAuth "PASSWORD GOES HERE"
        RedisStreamMaxSize 100
        NotifyStreamName sftp.longwood:notify
</IfModule mod_restnotify.c>
```

**NOTE:** This module's filesystem access is restricted by the chroot
"jail" if the "DefaultRoot" parameter is used to restrict the forked
protftpd server process that handles each client connection.  Thus,
if you restrict a user to ```DefaultRoot /home/%u``` the path of
```/var/run/redis/redis-server.sock``` will be inaccessible and the
module will complain (in the logs) that the path does not exist /
the connection will fail.
