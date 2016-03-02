Charon
======

A game authentication server, second try...

Installation
------------

Ensure you have a working Go build environment that can compile cgo packages.

    go get github.com/AlexMax/charon/...

License
-------

This software has been released under the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.html).  It seemed prudent to start with a license that ensures code freedom, because once you switch to a license that prioritizes developer freedom it's very hard to put the genie back in the bottle.  If you have a particular use case in mind where the AGPL would be problematic, however, I am open to alternative licensing arrangements.

I have also vendored Tad Glines' [srp](https://github.com/tadglines/go-pkgs/tree/master/crypto/srp) library.  I feel like the only fair thing to do is to continue to offer this modified library under its original [Apache 2.0](https://opensource.org/licenses/Apache-2.0) license.
