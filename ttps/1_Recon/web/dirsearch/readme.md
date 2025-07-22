### dirsearch

```sh
podman build -t dirsearch .
podman run -it --name dirsearch dirsearch

# Content Discovery ( Directory and File Bruteforcing ) example
dirsearch -e php,asp,aspx,jsp,py,txt,conf,config,bak,backup,swp,old,db,sql,asp,aspx,asp~,py~,rb,rb~,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp~,lock,log,rar,old,sql.gz,sql.zip,sql.tar.gz,sql~,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip -i 200 --full-url --deep-recursive -w /usr/share/wordlists/custom.txt --exclude-subdirs .well-known/,wp-includes/,wp-json/,faq/,Company/,Blog/,Careers/,Contact/,About/,IMAGE/,Images/,Logos/,Videos/,feed/,resources/,banner/,assets/,css/,fonts/,img/,images/,js/,media/,static/,templates/,uploads/,vendor/ --exclude-sizes 0B --skip-on-status 429 --random-agent -o rest.vulnweb.com.txt -u http://rest.vulnweb.com
```