{-# LANGUAGE OverloadedStrings #-}

module Server.Protocol.Shadowsocks.User (ServerUserManager, fromConfig, getUserByHash, userCount) where

import Common.Config (User (User))
import Common.Crypto.Aead (CipherKind)
import Common.Protocol.Shadowsocks.Aead2022 (decodeKey)
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser), ServerUserManager (ServerUserManager), getUserByHash, newServerUser, userCount)
import Control.Concurrent.STM (atomically)
import Control.Monad (forM_)
import qualified StmContainers.Map as STMMap

fromConfig :: CipherKind -> [User] -> IO ServerUserManager
fromConfig kind users = do
  validated <- mapM validate users
  atomically $ do
    manager@(ServerUserManager userMap) <- ServerUserManager <$> STMMap.new
    forM_ validated $ \user -> do
      let ServerUser _ _ identityHash = user
      _ <- STMMap.insert user identityHash userMap
      pure ()
    pure manager
  where
    validate (User name' password') = newServerUser name' <$> decodeKey kind "shadowsocks user key" password'
