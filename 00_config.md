### Sudo without password

````
$ sudo vi /etc/sudoers
tom ALL=(ALL) NOPASSWD:ALL
````

### user zen, without sudo

````
$ adduser zen
$ cat .bashrc
xhost +SI:localuser:zen
export DISPLAY=:0
Ou export DISPLAY=:1
````



### user yop, with sudo



### chrome




### code

````
$ mkdir  ~/code
$ cat go_code
code --user-data-dir argument ~/code
````

### config git

````
$ git config --global user.name "jossets"
$ git config --global user.email 13644560+jossets@users.noreply.github.com                                                                  
````


### Screenshot


shift+ImpEcran -> Save in ~/Images