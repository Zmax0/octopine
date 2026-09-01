{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Server.Protocol.Shadowsocks (Context (Context), newPacketCodec) where

import Common.Config (ServerConfig (cipher, host, password, port, user))
import Common.Crypto (Key)
import Common.Crypto.Aead (CipherKind, keySize)
import Common.Protocol.Shadowsocks.Aead (opensslBytesToKey)
import Common.Protocol.Shadowsocks.Aead2022 (isAead2022, passwordToKeys)
import Control.Concurrent.STM (atomically)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import qualified Data.TinyLRU as TinyLRU
import Server.Protocol (ServerProtocol (label, newServerCodec, newServerContext))
import qualified Server.Protocol.Shadowsocks.Codec as Codec
import qualified Server.Protocol.Shadowsocks.User as User

-- | properties
-- * @kind@
-- * @key@
-- * @salt cache@
-- * @user manager@
-- * @label@
-- * kind key saltCache userManager label
data Context = Context CipherKind Key Codec.SaltCache User.ServerUserManager String

instance Show Context where
  show (Context _ _ _ _ label') = label'

instance ServerProtocol Context Codec.PayloadCodec where
  newServerContext config = do
    userManager <- atomically $ User.fromConfig $ user config
    saltCache <- atomically $ TinyLRU.initTinyLRU maxBound
    let kind = cipher config
    key <- if isAead2022 kind then fst <$> passwordToKeys (password config) else return $ opensslBytesToKey (encodeUtf8 $ password config) (keySize kind)
    let label' = "shadowsocks|" ++ show kind ++ "|" ++ T.unpack (host config) ++ ":" ++ show (port config)
    return $ Context kind key saltCache userManager label'

  newServerCodec (Context kind key saltCache userManager _) chunk = do
    userCount' <- atomically $ User.userCount userManager
    let settings = Codec.ShadowsocksSettings kind key (userCount' > 0) saltCache userManager
    Codec.newPayloadCodec settings chunk

  label (Context _ _ _ _ label') = label'

newPacketCodec :: Context -> Codec.PacketCodec
newPacketCodec (Context kind key _ userManager _) = Codec.PacketCodec kind key userManager
