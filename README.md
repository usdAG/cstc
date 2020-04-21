*Copyright 2017-2020 usd AG*

Licensed under the *GNU General Public License, Version 3.0* (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at https://www.gnu.org/licenses/gpl-3.0.html

![CSTC](media/CSTC_White_Smaller.png)

# Cyber Security Transformation Chef

*The Cyber Security Transformation Chef* (*CSTC*) is a *Burp Suite* extension. It is build for security experts to
extend *Burp Suite* for chaining simple operations for each incomming or outgoing message.
It can also be used to quickly apply custom formatting for each message.

![CSTC-Workflow](media/CSTC_Workflow.gif)

## Introduction

[Burp Suite](https://portswigger.net/) is a general known tool which provides
a wide area of tools and functionality for conducting a web application penetration
test. One problem often encountered when using *Burp Suite* for certain types of
web applications is the lack of a quick extensibility or the capability
of conducting basic operations on incoming or outgoing messages.

*Burp Suite* provides some functionality which can be used to adapt to certain scenarios
(i.e. the *macro feature*), however it is a time consuming process, difficult to learn and error-prone.

With the years we developed a software which provides a GUI which is adapted from the well known
[CyberChef](https://gchq.github.io/CyberChef/) providing several small operations which can be chained
to conduct complicated input transformations. There is no need of further coding. The extension eliminates
the need of having several plugins for input and output transformations because it is build in a more generic way.

The *CSTC* is especially useful for using the already existing capabilities of *Burp Suite Professional* (*Burp Scanner*, *Backslash Powered Scanner*, ...)
on web applications using client side calculated *MACs*, sequence numbers, or similiar for request validation.
However, the *CSTC* does also perfectly intercoorperate with other *Burp Suite* features that are available in the *Community Edition* (*Repeater*, *Intruder*, ...).

It is also a great help for analyzing obfuscated *HTTP* based protocols because it can be used to de- and reobfuscate network traffic
passing through the proxy. In this way, the analyst can concentrate on the task of finding vulnerabilities
instead of writing a new extension for removing the obfuscation.

The plugin has been succesfully tested and decreased the time for performing tedious input and output transformations on *HTTP* messages.

## Prerequities

The *CSTC* can be used with either *Burp Suite Community Edition* or *Burp Suite Profesionnal*.

## Installation

The *CSTC* is currently not listed in the *Burp Extension Storage* (*BApp Store*), but will be added there as soon as *PortSwigger* acknolwedges the extension.

We suggest to pull the source code and build it yourself, because you should never trust binaries
and should always review the code which is used in a productive setting.

However, you can also pull a release from *GitHub* and install it by adding it to *Burp Suite*.

### Build Process

The build process is fairly easy. It currently requires a installed *JDK* and *Maven* to build.

You can build the extension with the following commands:

```
$ git clone https://github.com/usdAG/cstc.git
$ cd cstc
$ mvn package
```

*Maven* will automatically load the dependencies for building the extension and will build
a *Jar* containing all dependencies. The created Jar file ``CSTC-X.X.X-jar-with-dependencies`` in the target directory can be 
installed in *Burp Suite* using the ``Extender->Add->Extensiontype-java`` function.

## Usage

The tool uses a GUI which basic idea is similar to the [CyberChef](https://gchq.github.io/CyberChef/). However, it introduces
a new concept which we call *lanes*. The output of a *CSTC* transformation is always determined
from the the last *lane* which has an active operation. This initially takes getting used to, but quickly feels intuitive.
Take a look at our basic tutorial on [YouTube](https://www.youtube.com/watch?v=BUXvWfb_YWU) and make sure to read our initial
*CSTC* [blog post](https://herolab.usd.de/news-cyber-security-transformation-chef/).

## Feedback

We gladly appreciate all feedback, bug reports and feature requests.
Please understand that this tool is under active development and therefore will
probably contain some bugs :)
