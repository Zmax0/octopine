{-# LANGUAGE OverloadedStrings #-}

module Server.Protocol.Shadowsocks.User (ServerUserManager, fromConfig, getUserByHash, userCount) where

import qualified Codec.Binary.UTF8.Generic as UTF8
import Common.Config (User (User))
import Common.Protocol.Shadowsocks.User (ServerUser (ServerUser), ServerUserManager (ServerUserManager), getUserByHash, newServerUser, userCount)
import Control.Concurrent.STM (STM)
import Control.Monad (forM_)
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text as T
import qualified StmContainers.Map as STMMap

fromConfig :: [User] -> STM ServerUserManager
fromConfig users = do
  manager@(ServerUserManager userMap) <- ServerUserManager <$> STMMap.new
  forM_ users $ \(User name' password') -> do
    let key = B64.decodeLenient $ UTF8.fromString $ T.unpack password'
        user = newServerUser name' key
        ServerUser _ _ identityHash = user
    _ <- STMMap.insert user identityHash userMap
    pure ()
  pure manager
