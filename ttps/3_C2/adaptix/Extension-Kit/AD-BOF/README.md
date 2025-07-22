# AD-BOF

A BOFs that contains common enumeration and attack methods for Windows Active Directory.

![](_img/01.png)


## ldapsearch

Execute LDAP searches (NOTE: specify *,ntsecuritydescriptor as attribute parameter if you want all attributes + base64 encoded ACL of the objects, this can then be resolved using BOFHound. Could possibly break pagination, although everything seemed fine during testing.)

```
ldapsearch <query> <-attributes attributes> <-count count> <-scope scope> <-hostname hostname> <-dn dn> <-ldaps ldaps>
```



## Credits
* CS-Situational-Awareness-BOF - https://github.com/trustedsec/CS-Situational-Awareness-BOF
