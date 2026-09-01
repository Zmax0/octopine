module Common.Crypto (Key, Plaintext, Ciphertext) where

import Data.ByteString (StrictByteString)

type Key = StrictByteString

type Plaintext = StrictByteString

type Ciphertext = StrictByteString
