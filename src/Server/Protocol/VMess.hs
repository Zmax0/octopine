{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MultiParamTypeClasses #-}

module Server.Protocol.VMess (Context) where

import Common.Config (ServerConfig (host, port, user), User (password))
import Common.Crypto (Key)
import Common.Exception (AppExceptionKind (ConfigError), throwApp)
import qualified Common.Protocol.VMess.ID as ID
import qualified Data.Text as T
import qualified Data.UUID as UUID
import Server.Protocol (ServerProtocol (label, newServerCodec, newServerContext))
import qualified Server.Protocol.VMess.Codec as Codec

data Context = Context [Key] String deriving (Show)

instance ServerProtocol Context Codec.VMessCodec where
  newServerContext config = do
    keys <- mapM parseUser $ user config
    return $ Context keys ("vmess|" ++ T.unpack (host config) ++ ":" ++ show (port config))
    where
      parseUser currentUser =
        case UUID.fromText (password currentUser) of
          Just userId -> return $ ID.newID userId
          Nothing -> throwApp ConfigError $ "illegal uuid: " ++ T.unpack (password currentUser)

  newServerCodec (Context keys _) = Codec.newVMessCodec keys
  label (Context _ label') = label'
