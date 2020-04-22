# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  * *JsonSetter* (Set a field in JSON data).
  * *PostSetter* (Set a POST parameter).
  * *XmlSetter* (Set a field in XML data).
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
