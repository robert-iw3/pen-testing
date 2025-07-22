# LateralMovement-BOF

BOFs kit for lateral movements

![](_img/01.png)

## PsExec

Attempt to spawn a session on a remote target via PsExec

```
jump psexec <SvcBinary> <Computer>
```

![](_img/02.png)



## token make

Creates an impersonated token from a given credentials

```
token make <username> <password> <domain> <type>
```

![](_img/03.png)



## token steal

Steal access token from a process

```
token steal <pid>
```

