# Introduction

Ruler is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol. The main aim is abuse the client-side Outlook features and gain a shell remotely.

The full low-down on how Ruler was implemented and some background regarding MAPI can be found in our blog posts:
* [Ruler release]
* [Pass the Hash with Ruler]
* [Outlook forms and shells]
* [Outlook Home Page – Another Ruler Vector]

For a demo of it in action: [Ruler on YouTube]

## What does it do?

Ruler has multiple functions and more are planned. These include

* Enumerate valid users
* Create new malicious mail rules
* Dump the Global Address List (GAL)
* VBScript execution through forms
* VBScript execution through the Outlook Home Page

Ruler attempts to be semi-smart when it comes to interacting with Exchange and uses the Autodiscover service (just as your Outlook client would) to discover the relevant information.

# Getting Started

Compiled binaries for Linux, OSX and Windows are available. Find these in [Releases]
information about setting up Ruler from source is found in the [getting-started guide].

# Usage

Ruler has multiple functions, these have their own documentation that can be found in the [wiki]:

* [BruteForce] -- discover valid user accounts
* [Rules] -- perform the traditional, rule based attack
* [Forms] -- execute VBScript through forms
* [Homepage] -- use the Outlook 'home page' for shell and persistence
* [GAL] -- grab the Global Address List

# Attacking Exchange

The library included with Ruler allows for the creation of custom message using MAPI. This along with the Exchange documentation is a great starting point for new research. For an example of using this library in another project, see [SensePost Liniaal].

### Compile

```sh
make compile

# Linux
GOOS=linux GOARCH=amd64 go build -o ruler-linux64
sha256sum  ruler-linux64
f3b5e0f54f1da134c5d3c135f5be8ae7e85e499e8e73fabf87ffe010c23749ef  ruler-linux64

# Windows
GOOS=windows GOARCH=amd64 go build -o ruler-win64.exe
sha256sum  ruler-win64.exe
42e504f3d9d9800c1c75ff6d8c5433d801e7148760cba709fa3bd5dd8e4a0208  ruler-win64.exe
GOOS=darwin GOARCH=amd64 go build -o ruler-osx64
sha256sum  ruler-osx64
f3e108c7993b8d46c832ac2499a97395cc18fc9c4c1656acc25c969c7090ffcd  ruler-osx64
```


[Ruler Release]: <https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/>
[Pass the hash with Ruler]: <https://sensepost.com/blog/2017/pass-the-hash-with-ruler/>
[Outlook forms and shells]: <https://sensepost.com/blog/2017/outlook-forms-and-shells/>
[Outlook Home Page – Another Ruler Vector]: <https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/>
[Ruler on YouTube]:<https://www.youtube.com/watch?v=C07GS4M8BZk>
[Releases]: <https://github.com/sensepost/ruler/releases>
[SensePost Liniaal]:<https://github.com/sensepost/liniaal>
[wiki]:<https://github.com/sensepost/ruler/wiki>
[BruteForce]:<https://github.com/sensepost/ruler/wiki/Brute-Force>
[Rules]:<https://github.com/sensepost/ruler/wiki/Rules>
[Forms]:<https://github.com/sensepost/ruler/wiki/Forms>
[Homepage]:<https://github.com/sensepost/ruler/wiki/Homepage>
[GAL]:<https://github.com/sensepost/ruler/wiki/GAL>
[getting-started guide]:<https://github.com/sensepost/ruler/wiki/Getting-Started>
