module Common.Protocol.VMess.Aead.AuthID (createAuthID, match) where

import Common.Crypto (Key)
import Common.Crypto.Aes (aes128EcbNoPaddingDecrypt, aes128EcbNoPaddingEncrypt)
import Common.Dice (rollBytes)
import Common.Protocol.VMess (now)
import Common.Protocol.VMess.Aead (KDFSaltConst (AuthIDEncryptionKey, value))
import Common.Protocol.VMess.Aead.KDF (kdf16)
import Data.Binary.Get (getInt32be, getInt64be, runGet)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.ByteString.Builder (toLazyByteString, word32BE, word64BE)
import Data.Digest.CRC32 (CRC32 (crc32))
import Data.Int (Int64)

createAuthID :: Key -> Int64 -> IO StrictByteString
createAuthID key time = do
  let buffer1 = B.toStrict $ toLazyByteString $ word64BE $ fromIntegral time
  buffer2 <- rollBytes 4
  let crc32' = crc32 $ buffer1 <> buffer2
      buffer3 = B.toStrict $ toLazyByteString $ word32BE crc32'
      key' = kdf16 key [value AuthIDEncryptionKey]
  return $ aes128EcbNoPaddingEncrypt key' $ buffer1 <> buffer2 <> buffer3

match :: StrictByteString -> [Key] -> IO (Maybe Key)
match authID (key : keys) = do
  let cur = aes128EcbNoPaddingDecrypt (kdf16 key [value AuthIDEncryptionKey]) authID :: StrictByteString
      (l, r) = B.splitAt 12 cur
      now1 = runGet getInt64be (B.fromStrict $ B.take 8 l)
      crc32'' = runGet getInt32be (B.fromStrict r)
  now2 <- now
  if crc32 l == fromIntegral crc32'' && abs (now1 - now2) <= 120
    then pure $ Just key
    else match authID keys
match _ [] = pure Nothing
