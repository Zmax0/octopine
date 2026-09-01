{-# LANGUAGE TemplateHaskell #-}

module Common.Codec.Shadowsocks.TCP.Session (Session (Session), mode, address, identity) where

import Common.Codec.Shadowsocks.Identity (Identity, salt)
import Common.Network.Address (Address)
import Common.Protocol.Shadowsocks (Mode, Salt (Salt))
import Control.Lens (makeLenses, (^.))
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8)

data Session = Session {_mode :: Mode, _address :: Maybe Address, _identity :: Identity}

makeLenses ''Session

instance Show Session where
  show (Session _ address' identity') = do
    let (Salt salt') = identity' ^. salt
    "{salt = " ++ (T.unpack . decodeUtf8 . B64.encode) salt' ++ ", address = " ++ show address' ++ "}"
