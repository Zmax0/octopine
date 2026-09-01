{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Common.Config (ServerConfig (..), User (..), WsConfig, SslConfig, initConfig, readJSONConfig, initTlsParams, loadServerCredential) where

import Common (findArg)
import Common.Crypto.Aead (CipherKind (Aes128Gcm))
import Common.Exception (AppExceptionKind (ConfigError), throwApp)
import Common.Protocol (Protocol)
import Control.Monad (unless)
import Data.Aeson (FromJSON (..), eitherDecode, withObject, (.!=), (.:), (.:?))
import Data.ByteString.Lazy.UTF8 (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word16)
import GHC.Generics (Generic)
import qualified Network.TLS as TLS

data User = User {name :: Text, password :: Text} deriving (Show, Generic)

instance FromJSON User

data SslConfig = SslConfig {certificateFile :: Text, keyFile :: Text, serverName :: String} deriving (Show, Generic)

instance FromJSON SslConfig

newtype WsConfig = WsConfig {path :: Text} deriving (Show, Generic)

instance FromJSON WsConfig

data ServerConfig = ServerConfig {password :: Text, host :: Text, port :: Word16, protocol :: Protocol, cipher :: CipherKind, ssl :: Maybe SslConfig, quic :: Maybe SslConfig, ws :: Maybe WsConfig, user :: [User]} deriving (Show)

instance FromJSON ServerConfig where
  parseJSON = withObject "ServerConfig" $ \v ->
    ServerConfig
      <$> v .: "password"
      <*> v .: "host"
      <*> v .: "port"
      <*> v .: "protocol"
      <*> v .:? "cipher" .!= Aes128Gcm
      <*> v .:? "ssl"
      <*> v .:? "quic"
      <*> v .:? "ws"
      <*> v .:? "user" .!= []

initConfig :: [String] -> IO [ServerConfig]
initConfig args = do
  path' <- maybe (throwApp ConfigError "required arg: -config") return $ findArg args "-config"
  readJSONConfig path'

readJSONConfig :: FilePath -> IO [ServerConfig]
readJSONConfig path' = do
  file <- fromString <$> readFile path'
  either (throwApp ConfigError . ("read config failed: " ++)) return (eitherDecode file)

initTlsParams :: Maybe SslConfig -> IO (Maybe TLS.ServerParams)
initTlsParams = maybe (return Nothing) initTlsParams_
  where
    initTlsParams_ config' = do
      let serverName' = serverName config'
      credentials <- loadServerCredential config'
      return $
        Just
          TLS.defaultParamsServer
            { TLS.serverHooks =
                TLS.defaultServerHooks
                  { TLS.onServerNameIndication = \case
                      Just hostname -> do
                        unless (hostname == serverName') $ throwApp ConfigError $ "SNI failed, expected=" ++ serverName' ++ ", actual=" ++ hostname
                        return credentials
                      Nothing -> throwApp ConfigError "empty SNI"
                  },
              TLS.serverDebug = TLS.defaultDebugParams
            }

loadServerCredential :: SslConfig -> IO TLS.Credentials
loadServerCredential config' =
  TLS.credentialLoadX509 (T.unpack $ certificateFile config') (T.unpack $ keyFile config') >>= \case
    Left err -> throwApp ConfigError $ "failed to load certificate/key: " ++ show err
    Right c -> return $ TLS.Credentials [c]
