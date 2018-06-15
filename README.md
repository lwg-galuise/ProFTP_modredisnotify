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

sudo prcx -c -i -d mod_restnotify.c


Then the following section will need to be added to the ProFTPD
/etc/proftpd/modules.conf file (to load the module):

```
LoadModule mod_restnotify.c
```

Finally, the following configuration block will need to be added to
either the /etc/proftpd/proftpd.conf file or to one of the
/etc/proftpd/conf.d/ files:

```
<IfModule mod_restnotify.c>
        NotifyEndpoint iface.hq.longwoodgardens.org
</IfModule mod_restnotify.c>
```


There will most likely be more parameters to follow and this README.md
file will be upadated as those parameters are added.

Currently the "notify" portion of the code is not implemented and will
need to be added.  The module is currently capturing the needed data
for the notification and dumping it to the debug log.  However, it's a
proof of concept.

