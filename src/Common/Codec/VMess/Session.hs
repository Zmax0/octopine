{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.VMess.Session (Session (..), requestBodyIV, requestBodyKey, responseBodyIV, responseBodyKey, responseHeader, newServerSession) where

import Common.Crypto (Key)
import Common.Util (showBase64)
import Control.Lens (makeLenses)
import Crypto.Hash (SHA256 (..), hashWith)
import qualified Data.ByteArray as BA
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import GHC.Word (Word8)

data Session
  = ClientSession
      { _requestBodyIV :: StrictByteString,
        _requestBodyKey :: StrictByteString,
        _responseBodyIV :: StrictByteString,
        _responseBodyKey :: StrictByteString,
        _responseHeader :: Word8
      }
  | ServerSession
      { _requestBodyIV :: StrictByteString,
        _requestBodyKey :: StrictByteString,
        _responseBodyIV :: StrictByteString,
        _responseBodyKey :: StrictByteString,
        _responseHeader :: Word8
      }

makeLenses ''Session

newServerSession :: StrictByteString -> Key -> Word8 -> Session
newServerSession requestBodyIV' requestBodyKey' responseHeader' = do
  let responseBodyIV' = B.take 16 $ sha256 requestBodyIV'
      responseBodyKey' = B.take 16 $ sha256 requestBodyKey'
  ServerSession requestBodyIV' requestBodyKey' responseBodyIV' responseBodyKey' responseHeader'

sha256 :: StrictByteString -> StrictByteString
sha256 bytes = do
  let digest = hashWith SHA256 bytes
  BA.convert digest

instance Show Session where
  show session =
    "[RK="
      ++ showBase64 (_requestBodyKey session)
      ++ ",RI="
      ++ showBase64 (_requestBodyIV session)
      ++ ",SK="
      ++ showBase64 (_responseBodyKey session)
      ++ ",SI="
      ++ showBase64 (_responseBodyIV session)
      ++ ",SH="
      ++ show (_responseHeader session)
      ++ "]"
