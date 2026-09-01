{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Server.Protocol.Trojan (Context) where

import Common.Config (ServerConfig (host, password, port))
import Common.Protocol.Trojan (getContextKey)
import Data.ByteString (ByteString)
import qualified Data.Text as T
import Server.Protocol (ServerProtocol (label, newServerCodec, newServerContext))
import qualified Server.Protocol.Trojan.Codec as Codec

data Context = Context String CodecKey deriving (Show)

type CodecKey = ByteString

instance ServerProtocol Context Codec.TrojanCodec where
  newServerContext config = return $ Context ("trojan|" ++ T.unpack (host config) ++ ":" ++ show (port config)) (getContextKey $ password config)
  newServerCodec (Context _ key) = Codec.newTrojanCodec key
  label (Context label' _) = label'
