{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Common.Protocol (Protocol (..)) where

import Data.Aeson (FromJSON, ToJSON (toJSON), withText)
import Data.Aeson.Types (parseJSON)
import Data.Text (toLower)
import GHC.Generics (Generic)

data Protocol = Shadowsocks | VMess | Trojan deriving (Show, Eq, Generic)

instance FromJSON Protocol where
  parseJSON = withText "Protocol" $ \t -> case toLower t of
    "shadowsocks" -> return Shadowsocks
    "vmess" -> return VMess
    "trojan" -> return Trojan
    _ -> fail $ "Unknown protocol: " ++ show t

instance ToJSON Protocol where
  toJSON Shadowsocks = "shadowsocks"
  toJSON VMess = "vmess"
  toJSON Trojan = "trojan"
