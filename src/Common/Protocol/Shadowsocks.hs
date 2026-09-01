{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol.Shadowsocks (Mode (..), PacketId, Salt (Salt)) where

import Common.Util (showBase64)
import Data.Aeson (FromJSON (parseJSON), ToJSON (toJSON))
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import Data.Word (Word64)

data Mode = Client | Server deriving (Eq, Enum)

type PacketId = Word64

-- instance Enum Mode where
--   fromEnum Client = 0
--   fromEnum Server = 1

--   toEnum 0 = Client
--   toEnum 1 = Server
--   toEnum _ = error "illegal byte value"

newtype Salt = Salt StrictByteString

instance Show Salt where
  show (Salt value) = showBase64 value

instance ToJSON Salt where
  toJSON (Salt value) = toJSON $ B.unpack value

instance FromJSON Salt where
  parseJSON value = Salt . B.pack <$> parseJSON value
