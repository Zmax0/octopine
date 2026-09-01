{-# LANGUAGE OverloadedStrings #-}

-- |
-- AEAD-2022 Cipher Codec
-- Author: Zmax0
-- See: SIP022 AEAD-2022 Ciphers
-- <https://shadowsocks.org/doc/sip022.html>
module Common.Codec.Shadowsocks.Aead2022 (newEncoder, newDecoder, newTimestamp, nextPaddingLength, validateTimestamp) where

import Common.Codec.Shadowsocks.Aead (AeadDecoder (DecodeLength), AeadEncoder (AeadEncoder), newAuthenticator)
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind (..))
import Common.Exception (AppExceptionKind (ProtocolError), throwApp)
import Common.Protocol.Shadowsocks (Salt)
import Common.Protocol.Shadowsocks.Aead2022 (sessionSubKey)
import Control.Monad (when)
import Crypto.Number.Generate (generateBetween)
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.Int (Int64)
import qualified Data.Text.Lazy as TL
import Data.Time.Clock.System (SystemTime (systemSeconds), getSystemTime)
import Formatting (format, int, (%))

newEncoder :: CipherKind -> Key -> Salt -> AeadEncoder
newEncoder kind key salt' = do
  let key' = sessionSubKey key salt'
      auth = newAuthenticator kind key'
  AeadEncoder auth

newDecoder :: CipherKind -> Key -> Salt -> AeadDecoder
newDecoder kind key salt' = do
  let key' = sessionSubKey key salt'
      auth = newAuthenticator kind key'
  DecodeLength auth

newTimestamp :: IO Int64
newTimestamp = systemSeconds <$> getSystemTime

validateTimestamp :: Int64 -> IO ()
validateTimestamp timestamp = do
  now <- newTimestamp
  let diff = abs $ timestamp - now
  when (diff > 30) $ throwApp ProtocolError $ TL.unpack $ format ("invalid timestamp " % int % " - now " % int % " = " % int) timestamp now diff

nextPaddingLength :: (Num a) => StrictByteString -> IO a
nextPaddingLength msg = if B.null msg then pure 0 else fromInteger <$> generateBetween 0 900
