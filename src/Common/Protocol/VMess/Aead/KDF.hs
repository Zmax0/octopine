module Common.Protocol.VMess.Aead.KDF (kdf, kdf16, kdfN) where

import Common.Protocol.VMess.Aead (KDFSaltConst (VMessAeadKDF, value))
import Crypto.Hash (HashAlgorithm (hashBlockSize), SHA256 (..), hashWith)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import GHC.Bits (xor)

hmac' :: (BS.ByteString -> BS.ByteString) -> Int -> BS.ByteString -> BS.ByteString -> BS.ByteString
hmac' hash' blockSize key msg =
  let keyPadded
        | BS.length key > blockSize = hash' key
        | otherwise = BS.append key (BS.replicate (blockSize - BS.length key) 0)
      ipad = BS.map (`xor` 0x36) keyPadded
      opad = BS.map (`xor` 0x5c) keyPadded
      inner = hash' (BS.append ipad msg)
      outer = hash' (BS.append opad inner)
   in outer

kdf :: BS.ByteString -> [BS.ByteString] -> BS.ByteString
kdf key path =
  let path' = value VMessAeadKDF : path
      top = foldl (`hmac'` hashBlockSize SHA256) (BA.convert . hashWith SHA256) path'
   in top key

kdf16 :: BS.ByteString -> [BS.ByteString] -> BS.ByteString
kdf16 key path = kdfN key path 16

kdfN :: BS.ByteString -> [BS.ByteString] -> Int -> BS.ByteString
kdfN key path n = BS.take n $ kdf key path
