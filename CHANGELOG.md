# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.3.4] - 2024-11-01

### Added

* Add functionality to add or remove lanes
* Add CSTC Formatting Tab to Message Editor to view Formatting output
* Add Xml Setter Operation
* Add Strip Operation to remove leading or trailing whitespaces
* Add Collapse All / Expand All buttons to Operations Tree
* Add Remove Whitespace Operation

### Changed

* Refactor Http Xml Setter Operation
* Disable Bake button when Autobake is enabled
* Refactor Operations Tree for Outgoing/Incoming/Formatting to not contain redundant operations

### Fixed

* Fix UI bug of shifted component layout in Formatting Tab
* Fix appearance of Null Bytes in various operations
* Fix possible Race Condition on stored variables with Autobake enabled and Filter active


## [1.3.3] - 2024-07-30

### Fixed

* Fix Null Pointer Exception on startup


## [1.3.2] - 2024-07-16

### Added

* Add operation JSON Beautifier
* Add Sequencer filter option
* Add GZIP operation option to set the compression level
* Add comment function to operations and recipe lanes
* Add editable lane names

### Changed

* Fix the emergence of null bytes when using variables
* Fix GUI issues with using the operation Drag-and-Drop
* Change the saved recipe structure and add CSTC version, operation comments, lane comments and lane names
* Refactor operation button icons


## [1.3.1] - 2024-05-22

### Added

* Migrate to the new MontoyaAPI provided by Burp
* Redesign the existing filter selection for better usability
* Add ability to automatically save recipes in the Burp project file
* Filter state is now persistent upon restarting Burp / CSTC
* Add indication / warning if no filter has been selected (CSTC is inactive)
* Refactor and redesign behavior of "HTTP Request" module and add "Send Plain Request" operation
* Add an operation to set multipart/form-data parameters
* Add uppercase and lowercase operations for strings
* Add an option to URL safe encode and decode Base64 strings
* Add operation to generate JWT signatures
* Add operation to count executions of a specific operation / lane
* Add support for empty IVs in the "AES" operations
* Add an option to decide whether to append to or overwrite a file in the "File Write" operation
* Add HTTP/2 support
* Add operations for SM-2, SM-3, SM-4
* Change to Java Version 17
* Add CSTC introduction including demo
* Add Luhn checksum operation
* Add string concatenation operation

### Changed

* Fix compatibility issues with Burp's dark theme
* Fix an issue where CSTC interferes with requests when turned off
* Fix bugs related to loading and storing recipes
* Fix implementation of "HTTP Request" operation which caused exceptions
* Fix and add unit tests
* Fix UI bugs of the operation tree on the left hand side
* Refactor extractor and setter operations to match the new API, improve code quality and fix certain bugs (e.g. problem with multiple "Set-Cookie" headers)
* Fix Filter selection and its application
* Fix several issues regarding Conditionals
* Fix Formatting tab changes crashing Repeater tab
* Fix saving and loading Filter state inside Burp Project
* Fix Exception handling in Operation's perform method
* Fix CSTC lanes naming
* Fix JSON extractor only able to extract single values


## [1.3.0] - 2023-03-24

### Added

* Add Extender to the Filter Panel
* Addition of new Operations
  * Random Number
  * Random UUID
  * String Reverse
  * String Lowercase and String Uppercase
* Add clear button to the recipe panel

### Changed

* Fix bug related to insecure handling of XML input data
* Minor UI enhancements for tiling window managers
* Update all dependencies


## [1.2.1] - 2020-07-10

### Changed

* Fix bug in the *Save* function that prevented certain recipes from being saved
* Fix SoapMultiSignature operation (was not displayed in operations tree)
* Remove notifyChange listeners from *Button* objects
* Remove empty tooltipps from operation categories


## [1.2.0] - 2020-06-28

### Added

* Add additional operations:
  * *HTMLEncode* (Encode HTML special characters)
  * *HTMLDecode* (Decode HTML special characters)
  * *RsaEncrypt* (Encrypt data by using a public key)
  * *RsaDecrypt* (Decrypt data using a private key)
  * *RsaSignature* (Create an RSA signature)
  * *NoOperation* (Does nothing :D)
* Add *conditionals* operation class:
  * *StringContains* (Skip if input contains a string)
  * *StringMatch* (Skip if input matches a string)
  * *RegexMatch* (Skip if input matches the specified regex)
  * *NumberCompare* (Skip if comparison is true)
* Add *Maven CI* for the master and development branch
* Add *dependabot* config to prevent pushes to master

### Changed

* Byte operations now also allow multiple variables in one input field
* *jackson-core* and *jackson-databind* updated to current version
* Breakpoint operations now assign variables


## [1.1.1] - 2020-05-20

### Changed

* The variable replace function used ``replaceAll`` which caused problems with the new variable
  prefix ``$``. This was changed to ``replace``, as we don't need regex for variable replacement.
* The ``pom.xml`` of the project now specifies an explicit file encoding. This should make the build
  platform independent.


## [1.1.0] - 2020-05-20

### Added

* Add additional operations:
  * *LineExtractor* (Extracts a specific line from a *HTTP* request/response).
  * *LineSetter* (Sets a specific line in a *HTTP* request/response).
  * *RandomNumber* (Simply generates a random number).
  * *SetIfEmpty* (Sets a value if the incoming data is empty).
  * *SplitAndSelect* (Splits the input string and selects one item).

### Changed

* Change variable prefix to ``$`` (from previously ``§``)
* Update workflow demonstration (GIF inside README.md)


## [1.0.0] - 2020-04-22

### Added

* Support operating on raw byte data.
* Enable context menu inside the CSTC pane.
* Add additional operations:
  * *Divide* (Divide input by the given number).
  * *Multiply* (Multiply input with the given number).
  * *HttpCookieExtractor* (Extract cookies from *HTTP* requests).
  * *HeaderSetter* (Set *HTTP* headers).
  * *HttpSetBody* (Set *HTTP* body).
  * *HttpSetCookie* (Set *HTTP* cookie).
  * *HttpJsonSetter* (Set a JSON field in a HTTP request).
  * *JsonSetter* (Set a value inside of a JSON string).
  * *PostSetter* (Set a POST parameter).
  * *XmlSetter* (Set a XML field in a HTTP request ).
  * *HttpXmlExtractor* (Get a XML value from a HTTP request).
  * *HttpJsonExtractor* (Get a JSON value from a HTTP request).
* Add workflow demonstration in form of a GIF to README.md
* Add a changelog :)

### Changed

* Fix typos in several modules.
* Ignore the *IV* parameter when using encryption modules in *ECB* mode.
* Support *raw* encoding for *FormattedTextFields*.
* Make all operations work on raw bytes.
* Implement the so far unimplemented input and output modes for encryption modules.
* Correct syntax highlighting inside the CSTC pane.
* Fix bugs in several different modules.
* Update version of *jackson-databind*.
* Adjust image icons displayed inside the nodetree.

### Removed

* Remove *FlowControl* and *Language* operation categories, as they are currently unused.
* Remove *ReplaceBody* (was substituted by *HttpSetBody*).


## [0.1.1] - 2019-08-20

### Added

* Initial release.
