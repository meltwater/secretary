# Secretary
Secrets distribution for dynamic container environments

## TODO

* Sign/encrypt query parameters in decrypt request to daemon (pack all of them into envelope)
* Setuid secretary-cgi that decrypts the master key to avoid 
  giving `secretary daemon` direct access to master private key.
