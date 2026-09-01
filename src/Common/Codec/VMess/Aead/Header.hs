{-# LANGUAGE OverloadedStrings #-}

module Common.Codec.VMess.Aead.Header (seal, open) where

import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (Aes128Gcm), newCipherMethod)
import qualified Common.Crypto.Aead as Aead
import Common.Dice (rollBytes)
import Common.Logger (trace_)
import Common.Protocol.VMess (timestamp)
import Common.Protocol.VMess.Aead (KDFSaltConst (VMessHeaderPayloadAeadIV, VMessHeaderPayloadAeadKey, VMessHeaderPayloadLengthAeadIV, VMessHeaderPayloadLengthAeadKey), value)
import Common.Protocol.VMess.Aead.AuthID (createAuthID)
import Common.Protocol.VMess.Aead.KDF (kdf16, kdfN)
import Common.Util (decodeWord16BE, encodeLengthWord16be, showBase64)
import Control.Exception (SomeException)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Formatting (format, string, (%))

seal :: Key -> StrictByteString -> IO StrictByteString
seal key header = do
  generatedAuthID <- createAuthID key =<< timestamp 30
  connectionNonce <- rollBytes 8
  let cipherKind = Aes128Gcm
      lengthPlaintext = encodeLengthWord16be header
      lengthMethod = newCipherMethod cipherKind $ kdf16 key [value VMessHeaderPayloadLengthAeadKey, generatedAuthID, connectionNonce]
      lengthNonce = kdfN key [value VMessHeaderPayloadLengthAeadIV, generatedAuthID, connectionNonce] $ Aead.nonceSize cipherKind
      lengthCiphertext = Aead.encrypt lengthMethod lengthNonce B.empty lengthPlaintext
      headerMethod = newCipherMethod cipherKind $ kdf16 key [value VMessHeaderPayloadAeadKey, generatedAuthID, connectionNonce]
      headerNonce = kdfN key [value VMessHeaderPayloadAeadIV, generatedAuthID, connectionNonce] $ Aead.nonceSize cipherKind
      headerCiphertext = Aead.encrypt headerMethod headerNonce B.empty header
  return $ generatedAuthID <> lengthCiphertext <> connectionNonce <> headerCiphertext

-- | (`leftover`, `pending`)
open :: Key -> StrictByteString -> IO (Either SomeException (Maybe (StrictByteString, StrictByteString)))
open key ciphertext = do
  let cipherKind = Aes128Gcm
      tagSize = Aead.tagSize cipherKind
  if B.length ciphertext < (16 + 2 + tagSize + 8 + tagSize)
    then return $ Right Nothing
    else do
      let (authID, leftover) = B.splitAt 16 ciphertext
          (lengthCiphertext, leftover') = B.splitAt (2 + tagSize) leftover
          (connectionNonce, leftover'') = B.splitAt 8 leftover'
          nonceSize = Aead.nonceSize cipherKind
          lengthKey = kdf16 key [value VMessHeaderPayloadLengthAeadKey, authID, connectionNonce]
          lengthNonce = kdfN key [value VMessHeaderPayloadLengthAeadIV, authID, connectionNonce] nonceSize
          lengthMethod = newCipherMethod cipherKind lengthKey
      trace_ "c.p.v.a.Header" $ return $ format ("open header; AU=" % string % ", CN=" % string % ", LK=" % string % ", LN=" % string) (showBase64 authID) (showBase64 connectionNonce) (showBase64 lengthKey) (showBase64 lengthNonce)
      let lengthPlaintext = Aead.decrypt lengthMethod lengthNonce authID lengthCiphertext
          length' = decodeWord16BE lengthPlaintext
      if B.length leftover'' < length' + tagSize
        then return $ Right Nothing
        else do
          let (headerCiphertext, leftover''') = B.splitAt (length' + tagSize) leftover''
              headerMethod = newCipherMethod cipherKind $ kdf16 key [value VMessHeaderPayloadAeadKey, authID, connectionNonce]
              headerNonce = kdfN key [value VMessHeaderPayloadAeadIV, authID, connectionNonce] nonceSize
              headerPlaintext = Aead.decrypt headerMethod headerNonce authID headerCiphertext
          return $ Right $ Just (leftover''', headerPlaintext)
